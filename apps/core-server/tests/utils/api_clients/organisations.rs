use std::fmt::Display;

use serde_json::json;
use uuid::Uuid;

use super::{HttpClient, Response};

pub struct OrganisationsApi {
    client: HttpClient,
}

impl OrganisationsApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn create(&self, id: impl Into<Option<Uuid>>) -> Response {
        let body = match id.into() {
            Some(id) => json!({"id": id}),
            None => json!({}),
        };

        self.client.post("/api/organisation/v1", body).await
    }

    pub async fn list(&self) -> Response {
        self.client.get("/api/organisation/v1").await
    }

    pub async fn get(&self, id: &impl Display) -> Response {
        let url = format!("/api/organisation/v1/{id}");
        self.client.get(&url).await
    }
}
