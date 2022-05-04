use lazy_static::lazy_static;
use worker::*;

lazy_static! {
    pub static ref CORS: Cors = Cors::default()
        .with_max_age(86400)
        .with_origins(vec!["*"])
        .with_methods(vec![Method::Get, Method::Post, Method::Options,]);
}

pub fn log_request(req: &Request) {
    console_log!(
        "{} - [{}], located at: {:?}, within: {}",
        Date::now().to_string(),
        req.path(),
        req.cf().coordinates().unwrap_or_default(),
        req.cf().region().unwrap_or_else(|| "unknown region".into())
    );
}
