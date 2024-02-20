use super::{HttpClient, Response};

pub struct ConfigApi {
    client: HttpClient,
}

impl ConfigApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn get(&self) -> Response {
        self.client.get("/api/config/v1").await
    }
}
