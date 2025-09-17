use std::fmt::Display;

use serde::Serialize;
use serde_json::json;
use serde_with::skip_serializing_none;
use shared_types::IdentifierId;
use uuid::Uuid;

use super::{HttpClient, Response};

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

    pub async fn list(&self) -> Response {
        self.client.get("/api/organisation/v1").await
    }

    pub async fn get(&self, id: &impl Display) -> Response {
        let url = format!("/api/organisation/v1/{id}");
        self.client.get(&url).await
    }
}
