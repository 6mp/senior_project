pub mod todo_list {
    use serde::{Deserialize, Serialize};
    use std::fmt::{self, Display, Formatter};

    #[derive(Deserialize, Serialize, Debug)]
    pub struct Item {
        pub title: String,
        pub details: String,
        pub insert_time: String,
    }

    #[derive(Deserialize, Serialize, Debug)]
    pub struct Data {
        pub hashed_password: String,
        pub items: Vec<Item>,
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
        HeadersMissing,
    }

    impl Display for AuthError {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            match *self {
                AuthError::IncorrectPassword => write!(f, "username taken or incorrect password"),
                AuthError::AccountNotFound => write!(f, "no account exists with this username"),
                AuthError::HeadersMissing => write!(f, "missing username or password headers"),
            }
        }
    }
}
