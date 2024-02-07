use std::fmt::Display;

use serde_json::json;
use uuid::Uuid;

use super::{HttpClient, Response};

pub struct SSIApi {
    client: HttpClient,
}

impl SSIApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn temporary_connect(&self, credential_id: impl Display) -> Response {
        let url = format!(
            "/ssi/temporary-issuer/v1/connect?protocol=PROCIVIS_TEMPORARY&credential={credential_id}"
        );

        let body = json!({
          "did": "did:key:test"
        });

        self.client.post(&url, body).await
    }

    pub async fn temporary_submit(&self, credential_id: impl Display) -> Response {
        let url = format!("/ssi/temporary-issuer/v1/submit?credentialId={credential_id}");

        self.client.post(&url, None).await
    }

    pub async fn get_credential_offer(
        &self,
        credential_schema_id: impl Into<Uuid>,
        credential_id: impl Into<Uuid>,
    ) -> Response {
        let url = format!(
            "/ssi/oidc-issuer/v1/{}/offer/{}",
            credential_schema_id.into(),
            credential_id.into()
        );

        self.client.get(&url).await
    }

    pub async fn get_json_ld_context(&self, credential_schema_id: impl Into<Uuid>) -> Response {
        let url = format!("/ssi/context/v1/{}", credential_schema_id.into());
        self.client.get(&url).await
    }

    pub async fn get_oidc_verifier_presentation_definition(
        &self,
        proof_id: impl Display,
    ) -> Response {
        let url = format!("/ssi/oidc-verifier/v1/{proof_id}/presentation-definition");
        self.client.get(&url).await
    }
}
