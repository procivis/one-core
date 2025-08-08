use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{HttpClient, Response};
use crate::utils::serialization::query_time_urlencoded;

pub struct TrustAnchorsApi {
    client: HttpClient,
}

#[derive(Default)]
pub struct ListFilters {
    pub is_publisher: Option<bool>,
    pub name: Option<String>,
    pub created_date_after: Option<OffsetDateTime>,
    pub created_date_before: Option<OffsetDateTime>,
    pub last_modified_after: Option<OffsetDateTime>,
    pub last_modified_before: Option<OffsetDateTime>,
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
        let ListFilters {
            is_publisher,
            name,
            created_date_after,
            created_date_before,
            last_modified_after,
            last_modified_before,
        } = filters;

        let mut url = format!("/api/trust-anchor/v1?pageSize=20&page={page}");

        if let Some(name) = name {
            url += &format!("&name={name}")
        }

        if let Some(is_publisher) = is_publisher {
            url += &format!("&isPublisher={is_publisher}")
        }

        if let Some(date) = created_date_after {
            url += &format!("&{}", query_time_urlencoded("createdDateAfter", date));
        }
        if let Some(date) = created_date_before {
            url += &format!("&{}", query_time_urlencoded("createdDateBefore", date));
        }
        if let Some(date) = last_modified_after {
            url += &format!("&{}", query_time_urlencoded("lastModifiedAfter", date));
        }
        if let Some(date) = last_modified_before {
            url += &format!("&{}", query_time_urlencoded("lastModifiedBefore", date));
        }

        self.client.get(&url).await
    }

    pub async fn delete(&self, trust_anchor: impl Into<Uuid>) -> Response {
        let url = format!("/api/trust-anchor/v1/{}", trust_anchor.into());
        self.client.delete(&url).await
    }
}
