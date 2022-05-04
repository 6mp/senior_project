mod types;
mod utils;

use types::todo_list;
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

            if let (Ok(Some(user)), Ok(Some(pass))) =
                (headers.get("username"), headers.get("password"))
            {
                return match ctx
                    .kv("todo_list")?
                    .get(user.as_str())
                    .json::<todo_list::Data>()
                    .await?
                {
                    //account already exists
                    Some(account) => {
                        let hashed_pass = seahash::hash(pass.as_bytes()).to_string();

                        if hashed_pass != account.hashed_password {
                            return make_resp(
                                false,
                                "incorrect password or username already taken",
                            )?
                            .with_cors(&utils::CORS);
                        }

                        make_resp(true, "logged in")?.with_cors(&utils::CORS)
                    }
                    //account doesnt exist, insert into kv store
                    None => {
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
                };
            } else {
                make_resp(false, "missing username or password field")?.with_cors(&utils::CORS)
            }
        })
        .get_async("/items", |req, ctx| async move {
            let headers = req.headers();
            let make_resp = |success: bool, content: &str| {
                Response::from_json(&todo_list::Response {
                    success,
                    content: content.to_string(),
                })
            };
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
