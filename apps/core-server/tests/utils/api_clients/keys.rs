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
}
