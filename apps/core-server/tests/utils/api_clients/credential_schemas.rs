use std::fmt::Display;

use serde_json::json;
use uuid::Uuid;

use super::{HttpClient, Response};

pub struct CredentialSchemasApi {
    client: HttpClient,
}

impl CredentialSchemasApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn create(&self, name: &str, organisation_id: impl Into<Uuid>) -> Response {
        let body = json!({
          "claims": [
            {
              "datatype": "STRING",
              "key": "firstName",
              "required": true
            }
          ],
          "format": "JWT",
          "name": name,
          "organisationId": organisation_id.into(),
          "revocationMethod": "STATUSLIST2021"
        });

        self.client.post("/api/credential-schema/v1", body).await
    }

    pub async fn get(&self, schema_id: &impl Display) -> Response {
        let url = format!("/api/credential-schema/v1/{schema_id}");
        self.client.get(&url).await
    }

    pub async fn list(
        &self,
        page: u64,
        page_size: u64,
        organisation_id: &impl Display,
    ) -> Response {
        let url = format!("/api/credential-schema/v1?page={page}&pageSize={page_size}&organisationId={organisation_id}");
        self.client.get(&url).await
    }

    pub async fn delete(&self, schema_id: &impl Display) -> Response {
        let url = format!("/api/credential-schema/v1/{schema_id}");
        self.client.delete(&url).await
    }
}
