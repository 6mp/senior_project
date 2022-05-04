pub mod todo_list {
    use serde::{Deserialize, Serialize};

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
}
