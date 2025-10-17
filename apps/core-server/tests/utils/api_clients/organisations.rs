use std::fmt::Display;

use serde::Serialize;
use serde_json::json;
use serde_with::skip_serializing_none;
use shared_types::IdentifierId;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{HttpClient, Response};
use crate::utils::serialization::query_time_urlencoded;

#[derive(Debug, Clone)]
pub struct OrganisationFilters {
    pub page: u64,
    pub page_size: u64,
    pub name: Option<String>,

    pub created_date_after: Option<OffsetDateTime>,
    pub created_date_before: Option<OffsetDateTime>,
    pub last_modified_after: Option<OffsetDateTime>,
    pub last_modified_before: Option<OffsetDateTime>,
}

pub struct OrganisationsApi {
    client: HttpClient,
}

#[skip_serializing_none]
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpsertParams {
    pub deactivate: Option<bool>,
    pub name: Option<String>,
    pub wallet_provider: Option<Option<String>>,
    pub wallet_provider_issuer: Option<Option<IdentifierId>>,
}

impl OrganisationsApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn create(&self, id: impl Into<Option<Uuid>>, name: Option<&str>) -> Response {
        let mut body = match id.into() {
            Some(id) => json!({"id": id}),
            None => json!({}),
        };

        if let Some(name) = name {
            body["name"] = json!(name);
        }

        self.client.post("/api/organisation/v1", body).await
    }

    pub async fn upsert(&self, id: &impl Display, params: UpsertParams) -> Response {
        self.client
            .patch(
                &format!("/api/organisation/v1/{id}"),
                Some(serde_json::to_value(params).unwrap()),
            )
            .await
    }

    pub async fn list(
        &self,
        OrganisationFilters {
            page,
            page_size,
            name,
            created_date_after,
            created_date_before,
            last_modified_after,
            last_modified_before,
        }: OrganisationFilters,
    ) -> Response {
        let mut url = format!("/api/organisation/v1?page={page}&pageSize={page_size}");

        if let Some(name) = name {
            url += &format!("&name={name}");
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

    pub async fn get(&self, id: &impl Display) -> Response {
        let url = format!("/api/organisation/v1/{id}");
        self.client.get(&url).await
    }
}
