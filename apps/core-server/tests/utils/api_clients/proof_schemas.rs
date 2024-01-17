use serde_json::json;
use uuid::Uuid;

use super::{HttpClient, Response};

pub struct ProofSchemasApi {
    client: HttpClient,
}

impl ProofSchemasApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn create(
        &self,
        name: &str,
        claim_schema_id: impl Into<Uuid>,
        organisation_id: impl Into<Uuid>,
    ) -> Response {
        let body = json!({
          "claimSchemas": [
            {
              "id": claim_schema_id.into(),
              "required": true
            }
          ],
          "expireDuration": 0,
          "name": name,
          "organisationId": organisation_id.into(),
        });

        self.client.post("/api/proof-schema/v1", body).await
    }
}
