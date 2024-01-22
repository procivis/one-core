use std::fmt::Display;

use serde_json::json;
use uuid::Uuid;

use super::{HttpClient, Response};

pub struct CredentialsApi {
    client: HttpClient,
}

impl CredentialsApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn create(
        &self,
        credential_schema_id: impl Into<Uuid>,
        transport: impl Into<String>,
        issuer_did: impl Into<Uuid>,
        claim_id: impl Into<Uuid>,
    ) -> Response {
        let body = json!({
          "credentialSchemaId": credential_schema_id.into(),
          "transport": transport.into(),
          "issuerDid": issuer_did.into(),
          "claimValues": [
                {
                    "claimId": claim_id.into(),
                    "value": "some value"
                }
            ]
        });

        self.client.post("/api/credential/v1", body).await
    }

    pub async fn list(
        &self,
        page: u64,
        size: u64,
        organisation_id: &impl Display,
        role: Option<&str>,
        name: Option<&str>,
    ) -> Response {
        let mut url = format!(
            "/api/credential/v1?page={page}&pageSize={size}&organisationId={organisation_id}"
        );
        if let Some(role) = role {
            url += &format!("&role={role}")
        }
        if let Some(name) = name {
            url += &format!("&name={name}")
        }
        self.client.get(&url).await
    }

    pub async fn get(&self, id: &impl Display) -> Response {
        let url = format!("/api/credential/v1/{id}");
        self.client.get(&url).await
    }

    pub async fn delete(&self, id: &impl Display) -> Response {
        let url = format!("/api/credential/v1/{id}");
        self.client.delete(&url).await
    }

    pub async fn revoke(&self, id: &impl Display) -> Response {
        let url = format!("/api/credential/v1/{id}/revoke");
        self.client.post(&url, None).await
    }

    pub async fn revocation_check(&self, credential_id: impl Into<Uuid>) -> Response {
        let body = json!({
          "credentialIds": vec![credential_id.into()]
        });

        self.client
            .post("/api/credential/v1/revocation-check", body)
            .await
    }

    pub async fn share(&self, id: &impl Display) -> Response {
        let url = format!("/api/credential/v1/{id}/share");
        self.client.post(&url, None).await
    }
}
