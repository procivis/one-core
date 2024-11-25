use serde_json::json;
use uuid::Uuid;

use super::{HttpClient, Response};

pub struct TrustAnchorsApi {
    client: HttpClient,
}

pub struct ListFilters {
    pub is_publisher: Option<bool>,
    pub name: Option<String>,
}

impl TrustAnchorsApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn create(&self, name: &str, type_: &str, is_publisher: bool) -> Response {
        let body = json!({
          "name": name,
          "type": type_,
          "isPublisher": is_publisher,
        });

        self.client.post("/api/trust-anchor/v1", body).await
    }

    pub async fn get(&self, trust_anchor: impl Into<Uuid>) -> Response {
        let url = format!("/api/trust-anchor/v1/{}", trust_anchor.into());
        self.client.get(&url).await
    }

    pub async fn list(&self, page: usize, filters: ListFilters) -> Response {
        let ListFilters { is_publisher, name } = filters;

        let mut url = format!("/api/trust-anchor/v1?pageSize=20&page={page}");

        if let Some(name) = name {
            url += &format!("&name={name}")
        }

        if let Some(is_publisher) = is_publisher {
            url += &format!("&isPublisher={is_publisher}")
        }

        self.client.get(&url).await
    }

    pub async fn delete(&self, trust_anchor: impl Into<Uuid>) -> Response {
        let url = format!("/api/trust-anchor/v1/{}", trust_anchor.into());
        self.client.delete(&url).await
    }
}
