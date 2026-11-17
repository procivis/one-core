use std::fmt::Display;

use serde::Serialize;
use serde_json::json;
use serde_with::skip_serializing_none;
use shared_types::{ClaimSchemaId, CredentialSchemaId, OrganisationId};
use uuid::Uuid;

use super::{HttpClient, Response};

pub struct ProofSchemasApi {
    client: HttpClient,
}

#[skip_serializing_none]
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateProofSchemaParams {
    pub expire_duration: Option<u32>,
    pub proof_input_schemas: Option<Vec<UpdateProofInputSchemaParams>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateProofInputSchemaParams {
    pub credential_schema_id: CredentialSchemaId,
    pub formats: Vec<String>,
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
        let proof_input_schema = json!({
            "claimSchemas": claims.map(|(id, required)| json!({
                "id": id,
                "required": required
            })).collect::<Vec<_>>(),
            "credentialSchemaId": credential_schema_id.into(),
        });

        let body = json!({
            "expireDuration": 0,
            "name": name,
            "organisationId": organisation_id.into(),
            "proofInputSchemas": [proof_input_schema]
        });

        self.client.post("/api/proof-schema/v1", body).await
    }

    pub async fn delete(&self, proof_schema_id: impl Into<Uuid>) -> Response {
        let proof_schema_id = proof_schema_id.into();
        let url = format!("/api/proof-schema/v1/{proof_schema_id}");
        self.client.delete(&url).await
    }

    pub async fn get(&self, proof_schema_id: impl Into<Uuid>) -> Response {
        let proof_schema_id = proof_schema_id.into();
        let url = format!("/api/proof-schema/v1/{proof_schema_id}");
        self.client.get(&url).await
    }

    pub async fn update(
        &self,
        proof_schema_id: impl Display,
        params: UpdateProofSchemaParams,
    ) -> Response {
        let url = format!("/api/proof-schema/v1/{proof_schema_id}");
        self.client
            .patch(&url, Some(serde_json::to_value(params).unwrap()))
            .await
    }

    pub async fn share(&self, proof_schema_id: impl Into<Uuid>) -> Response {
        let url = format!("/api/proof-schema/v1/{}/share", proof_schema_id.into());
        self.client.post(&url, None).await
    }

    pub async fn import(
        &self,
        proof_schema: impl Into<serde_json::Value>,
        organisation_id: OrganisationId,
    ) -> Response {
        let schema = proof_schema.into();

        self.client
            .post(
                "/api/proof-schema/v1/import",
                Some(json!({
                    "schema": schema,
                    "organisationId": organisation_id
                })),
            )
            .await
    }

    pub async fn create_with_multiple_schemas(
        &self,
        name: &str,
        organisation_id: impl Into<Uuid>,
        proof_input_schemas: impl Into<serde_json::Value>,
    ) -> Response {
        let body = json!({
            "expireDuration": 0,
            "name": name,
            "organisationId": organisation_id.into(),
            "proofInputSchemas": proof_input_schemas.into()
        });

        self.client.post("/api/proof-schema/v1", body).await
    }
}
