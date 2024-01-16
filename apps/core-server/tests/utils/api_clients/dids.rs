use std::fmt::Display;

use serde_json::json;
use uuid::Uuid;

use super::{HttpClient, Response};

pub struct DidsApi {
    client: HttpClient,
}

impl DidsApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn create(
        &self,
        organisation_id: impl Into<Uuid>,
        key_id: impl Into<Uuid>,
        method: &str,
        name: &str,
    ) -> Response {
        let key_id = key_id.into();
        let body = json!({
          "keys": {
            "assertion": [
              key_id
            ],
            "authentication": [
              key_id
            ],
            "capabilityDelegation": [
              key_id
            ],
            "capabilityInvocation": [
              key_id
            ],
            "keyAgreement": [
              key_id
            ]
          },
          "method": method,
          "name": name,
          "organisationId": organisation_id.into(),
          "params": {}
        });

        self.client.post("/api/did/v1", body).await
    }

    pub async fn list(
        &self,
        page: u64,
        page_size: u64,
        organisation_id: &impl Display,
        deactivated: bool,
    ) -> Response {
        let url = format!("/api/did/v1?page={page}&pageSize={page_size}&organisationId={organisation_id}&deactivated={deactivated}");
        self.client.get(&url).await
    }

    pub async fn get(&self, did_id: &impl Display) -> Response {
        let url = format!("/api/did/v1/{did_id}");
        self.client.get(&url).await
    }

    pub async fn deactivate(&self, did_id: &impl Display) -> Response {
        let url = format!("/api/did/v1/{did_id}");
        let body = json!({
            "deactivated": true,
        });
        self.client.patch(&url, body).await
    }
}
