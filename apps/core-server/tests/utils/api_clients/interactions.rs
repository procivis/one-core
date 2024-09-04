use serde_json::json;
use shared_types::{CredentialId, DidId, KeyId, OrganisationId};
use uuid::Uuid;

use super::{HttpClient, Response};

pub struct InteractionsApi {
    client: HttpClient,
}

pub struct SubmittedCredential {
    pub proof_input_id: String,
    pub credential_id: CredentialId,
    pub claims_ids: Vec<Uuid>,
}

impl InteractionsApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn handle_invitation(
        &self,
        organisation_id: impl Into<OrganisationId>,
        url: &str,
    ) -> Response {
        let body = json!({
          "organisationId": organisation_id.into(),
          "url": url,
        });

        self.client
            .post("/api/interaction/v1/handle-invitation", body)
            .await
    }

    pub async fn issuance_accept(
        &self,
        interaction_id: impl Into<Uuid>,
        did_id: impl Into<DidId>,
        key_id: impl Into<Option<KeyId>>,
    ) -> Response {
        let body = json!({
          "interactionId": interaction_id.into(),
          "didId": did_id.into(),
          "keyId": key_id.into(),
        });

        self.client
            .post("/api/interaction/v1/issuance-accept", body)
            .await
    }

    pub async fn issuance_reject(&self, interaction_id: impl Into<Uuid>) -> Response {
        let body = json!({
          "interactionId": interaction_id.into(),
        });

        self.client
            .post("/api/interaction/v1/issuance-reject", body)
            .await
    }

    pub async fn presentation_submit(
        &self,
        interaction_id: Uuid,
        did_id: DidId,
        credentials: Vec<SubmittedCredential>,
    ) -> Response {
        let mut submit_credentials: serde_json::Map<String, serde_json::Value> = Default::default();
        for credential in credentials {
            submit_credentials.insert(
                credential.proof_input_id,
                json!({
                    "credentialId": credential.credential_id,
                    "submitClaims": credential.claims_ids,
                }),
            );
        }

        let body = json!({
          "interactionId": interaction_id,
          "didId": did_id,
          "submitCredentials": serde_json::Value::Object(submit_credentials)
        });

        self.client
            .post("/api/interaction/v1/presentation-submit", body)
            .await
    }
}
