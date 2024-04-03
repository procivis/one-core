use serde_json::json;
use shared_types::ClaimSchemaId;
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
        organisation_id: impl Into<Uuid>,
        claims: impl Iterator<Item = (ClaimSchemaId, bool)>,
        credential_schema_id: impl Into<Uuid>,
    ) -> Response {
        let body = json!({
          "expireDuration": 0,
          "name": name,
          "organisationId": organisation_id.into(),
          "proofInputSchemas": [
            {
              "validityConstraint": 10,
              "claimSchemas": claims.map(|(id, required)| json!(
                {
                    "id": id,
                    "required": required
                }
              )).collect::<Vec<_>>(),
              "credentialSchemaId": credential_schema_id.into(),
            }
          ]
        });

        self.client.post("/api/proof-schema/v1", body).await
    }

    pub async fn delete(&self, proof_schema_id: impl Into<Uuid>) -> Response {
        let proof_schema_id = proof_schema_id.into();
        let url = format!("/api/proof-schema/v1/{proof_schema_id}");
        self.client.delete(&url).await
    }
}
