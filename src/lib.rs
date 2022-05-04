mod types;
mod utils;

use types::todo_list::{self, AuthError};
use worker::*;

fn preflight_response(headers: &worker::Headers, cors_origin: &str) -> Result<Response> {
    let origin = match headers.get("Origin").unwrap() {
        Some(value) => value,
        None => return Response::empty(),
    };
    let mut headers = worker::Headers::new();
    headers.set("Access-Control-Allow-Headers", "*")?;
    headers.set("Access-Control-Allow-Methods", "*")?;

    for origin_element in cors_origin.split(',') {
        if origin.eq(origin_element) {
            headers.set("Access-Control-Allow-Origin", &origin)?;
            break;
        }
    }
    headers.set("Access-Control-Max-Age", "86400")?;
    Ok(Response::empty()
        .unwrap()
        .with_headers(headers)
        .with_status(204))
}

async fn authenticate(
    headers: &worker::Headers,
    kv: worker::kv::KvStore,
) -> std::result::Result<todo_list::Data, AuthError> {
    if let (Ok(Some(user)), Ok(Some(pass))) = (headers.get("username"), headers.get("password")) {
        return match kv
            .get(user.as_str())
            .json::<todo_list::Data>()
            .await
            .unwrap()
        {
            //account already exists
            Some(account) => {
                let hashed_pass = seahash::hash(pass.as_bytes()).to_string();

                if hashed_pass != account.hashed_password {
                    return Err(AuthError::IncorrectPassword);
                }

                Ok(account)
            }
            //account not in kv store
            None => Err(AuthError::AccountNotFound),
        };
    }

    Err(AuthError::HeadersMissing)
}

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: worker::Context) -> Result<Response> {
    utils::log_request(&req);

    let router = Router::new();

    router
        .get_async("/login", |req, ctx| async move {
            let headers = req.headers();
            let make_resp = |success: bool, content: &str| {
                Response::from_json(&todo_list::Response {
                    success,
                    content: content.to_string(),
                })
            };

            match authenticate(headers, ctx.kv("todo_list")?).await {
                Ok(_account) => make_resp(true, "logged in")?.with_cors(&utils::CORS),
                Err(e) => match e {
                    AuthError::IncorrectPassword => {
                        make_resp(false, "incorrect password or username already taken")?
                            .with_cors(&utils::CORS)
                    }
                    AuthError::AccountNotFound => {
                        //i know none of these unwraps will fail because the authenticate function has already checked if these headers exist
                        let user = headers.get("password")?.unwrap();
                        let pass = headers.get("password")?.unwrap();
                        let hashed_pass = seahash::hash(pass.as_bytes()).to_string();

                        ctx.kv("todo_list")?
                            .put(
                                user.as_str(),
                                todo_list::Data {
                                    hashed_password: hashed_pass,
                                    items: Vec::new(),
                                },
                            )?
                            .execute()
                            .await?;

                        make_resp(true, "created account")?.with_cors(&utils::CORS)
                    }
                    AuthError::HeadersMissing => {
                        make_resp(false, "missing username or password headers")?
                            .with_cors(&utils::CORS)
                    }
                },
            }
        })
        .get_async("/items", |req, ctx| async move {
            /*            let headers = req.headers();
            let make_resp = |success: bool, content: &str| {
                Response::from_json(&todo_list::Response {
                    success,
                    content: content.to_string(),
                })
            };

            if let (Ok(Some(user)), Ok(Some(pass))) =
                (headers.get("username"), headers.get("password"))
            {
                return match ctx
                    .kv("todo_list")?
                    .get(user.as_str())
                    .json::<todo_list::Data>()
                    .await? {};
            }*/
            Response::ok("w")
        })
        .options("/login", |req, ctx| {
            preflight_response(req.headers(), &ctx.var("CORS_ORIGIN")?.to_string())
        })
        .options("/items", |req, ctx| {
            preflight_response(req.headers(), &ctx.var("CORS_ORIGIN")?.to_string())
        })
        .run(req, env)
        .await
}
