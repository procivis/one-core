use super::{HttpClient, Response};

pub struct JsonLdApi {
    client: HttpClient,
}

impl JsonLdApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn resolve(&self, url: &str) -> Response {
        let url = format!("/api/jsonld-context/v1?url={url}");
        self.client.get(&url).await
    }
}
