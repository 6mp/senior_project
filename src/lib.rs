mod types;
mod utils;

use types::todo_list::{self, AuthError};
use worker::*;

fn preflight_response() -> Result<Response> {
    let mut headers = worker::Headers::new();
    headers.set("Access-Control-Allow-Headers", "*")?;
    headers.set("Access-Control-Allow-Methods", "*")?;
    headers.set("Access-Control-Allow-Origin", "*")?;
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

fn handle_auth_error(
    make_resp: fn(bool, String) -> Result<Response>,
    e: AuthError,
) -> Result<Response> {
    match e {
        AuthError::IncorrectPassword => make_resp(true, e.to_string())?.with_cors(&utils::CORS),
        AuthError::AccountNotFound => make_resp(true, e.to_string())?.with_cors(&utils::CORS),
        AuthError::HeadersMissing => make_resp(true, e.to_string())?.with_cors(&utils::CORS),
    }
}

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: worker::Context) -> Result<Response> {
    utils::log_request(&req);

    let router = Router::new();

    router
        .get_async("/login", |req, ctx| async move {
            let headers = req.headers();
            let make_resp = |success: bool, content: String| {
                Response::from_json(&todo_list::Response { success, content })
            };

            match authenticate(headers, ctx.kv("todo_list")?).await {
                Ok(_account) => make_resp(true, "logged in".to_string())?.with_cors(&utils::CORS),
                Err(e) => match e {
                    AuthError::IncorrectPassword => {
                        make_resp(false, e.to_string())?.with_cors(&utils::CORS)
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

                        make_resp(true, "created account".to_string())?.with_cors(&utils::CORS)
                    }
                    AuthError::HeadersMissing => {
                        make_resp(false, e.to_string())?.with_cors(&utils::CORS)
                    }
                },
            }
        })
        .get_async("/get_items", |req, ctx| async move {
            let headers = req.headers();
            let make_resp = |success: bool, content: String| {
                Response::from_json(&todo_list::Response { success, content })
            };

            match authenticate(headers, ctx.kv("todo_list")?).await {
                Ok(account) => make_resp(true, serde_json::to_string(&account.items).unwrap()),
                Err(e) => handle_auth_error(make_resp, e),
            }
        })
        .post_async("/put_item", |mut req, ctx| async move {
            let headers = req.headers();
            let make_resp = |success: bool, content: String| {
                Response::from_json(&todo_list::Response { success, content })
            };

            match authenticate(&headers, ctx.kv("todo_list")?).await {
                Ok(mut account) => {
                    let item = req.json::<todo_list::Item>().await?;
                    account.items.push(item);
                    /*                    ctx.kv("todo_list")?
                    .put(headers.get("username").unwrap().unwrap().as_str(), account);*/
                    Response::ok("temp")
                }
                Err(e) => handle_auth_error(make_resp, e),
            }
        })
        .options("/login", |_, _| preflight_response())
        .options("/items", |_, _| preflight_response())
        .run(req, env)
        .await
}
