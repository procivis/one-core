use serde_json::json;

use super::{HttpClient, Response};

pub struct TasksApi {
    client: HttpClient,
}

impl TasksApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn run(&self, task: &str) -> Response {
        let body = json!({
          "name": task,
          "params": {}
        });

        self.client.post("/api/task/v1/run", body).await
    }
}
