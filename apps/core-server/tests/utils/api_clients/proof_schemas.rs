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

    pub async fn delete(&self, proof_schema_id: impl Into<Uuid>) -> Response {
        let proof_schema_id = proof_schema_id.into();

        let url = format!("/api/proof-schema/v1/{proof_schema_id}");

        self.client.delete(&url).await
    }
}
