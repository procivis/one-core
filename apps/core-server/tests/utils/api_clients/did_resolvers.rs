use std::fmt::Display;

use super::{HttpClient, Response};

pub struct DidResolversApi {
    client: HttpClient,
}

impl DidResolversApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn resolve(&self, did_value: impl Display) -> Response {
        let url = format!("/api/did-resolver/v1/{did_value}");
        self.client.get(&url).await
    }
}
