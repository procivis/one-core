use crate::utils::api_clients::{HttpClient, Response};

pub struct OtherApi {
    client: HttpClient,
}

impl OtherApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn metrics(&self) -> Response {
        self.client.get("/metrics").await
    }

    pub async fn build_info(&self) -> Response {
        self.client.get("/api/build-info/v1").await
    }

    pub async fn health(&self) -> Response {
        self.client.get("/health").await
    }

    pub async fn openapi_json(&self) -> Response {
        self.client.get("/api-docs/openapi.json").await
    }

    pub async fn openapi_yaml(&self) -> Response {
        self.client.get("/api-docs/openapi.yaml").await
    }
}
