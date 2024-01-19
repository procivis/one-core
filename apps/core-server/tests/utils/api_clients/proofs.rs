use std::fmt::Display;

use super::{HttpClient, Response};

pub struct ProofsApi {
    client: HttpClient,
}

impl ProofsApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn get(&self, id: impl Display) -> Response {
        let url = format!("/api/proof-request/v1/{id}");
        self.client.get(&url).await
    }
}
