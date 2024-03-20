use one_core::model::credential_schema::CredentialSchema;
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
        organisation_id: impl Into<Uuid>,
        credential_schema: &CredentialSchema,
    ) -> Response {
        let claim = &credential_schema.claim_schemas.as_ref().unwrap()[0];

        let body = json!({
          "expireDuration": 0,
          "name": name,
          "organisationId": organisation_id.into(),
          "proofInputSchemas": [
            {
              "validityConstraint": 10,
              "claimSchemas": [
                {
                  "id": claim.schema.id,
                  "required": claim.required
                }
              ],
              "credentialSchemaId": credential_schema.id,
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
