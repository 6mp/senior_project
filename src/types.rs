pub mod todo_list {
    use serde::{Deserialize, Serialize};
    use std::error::Error;
    use std::fmt;
    use std::fmt::{Display, Formatter};

    #[derive(Deserialize, Serialize, Debug)]
    pub struct Item {
        pub task: String,
        pub insert_time: String,
    }

    #[derive(Deserialize, Serialize, Debug)]
    pub struct Data {
        pub hashed_password: String,
        pub items: Vec<Data>,
    }

    #[derive(Deserialize, Serialize, Debug)]
    pub struct Response {
        pub success: bool,
        pub content: String,
    }

    #[derive(Debug)] // Allow the use of "{:?}" format specifier
    pub enum AuthError {
        IncorrectPassword,
        AccountNotFound,
        HeadersMissing
    }

    impl Display for AuthError {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            todo!()
        }
    }

    impl Error for AuthError {
        fn description(&self) -> &str {
            match *self {
                AuthError::IncorrectPassword => "username taken or incorrect password",
                AuthError::AccountNotFound => "no account exists with thi username",
                AuthError::HeadersMissing => "missing username or password headers",
            }
        }
    }
}
