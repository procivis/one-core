use serde_json::json;
use uuid::Uuid;

use super::{HttpClient, Response};

pub struct KeysApi {
    client: HttpClient,
}

impl KeysApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn create(
        &self,
        organisation_id: impl Into<Uuid>,
        key_type: &str,
        name: &str,
    ) -> Response {
        let body = json!({
          "keyParams": {},
          "keyType": key_type,
          "name": name,
          "organisationId": organisation_id.into(),
          "storageParams": {},
          "storageType": "INTERNAL"
        });

        self.client.post("/api/key/v1", body).await
    }

    pub async fn generate_csr(&self, key_id: &str) -> Response {
        let body = json!({
            "exp": "2023-06-09T14:19:57.000Z",
            "nbf": "2023-06-09T14:19:58.000Z",
            "profile": "MDL",
            "subject": {
                "commonName": "test",
                "countryName": "CH",
            }
        });

        self.client
            .post(&format!("/api/key/v1/{key_id}/generate-csr"), body)
            .await
    }
}
