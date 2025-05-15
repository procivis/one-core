use serde_json::json;
use shared_types::{DidId, KeyId, OrganisationId};
use uuid::Uuid;

use super::{HttpClient, Response};

pub struct InteractionsApi {
    client: HttpClient,
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
        tx_code: impl Into<Option<&str>>,
    ) -> Response {
        let body = json!({
          "interactionId": interaction_id.into(),
          "didId": did_id.into(),
          "keyId": key_id.into(),
          "txCode": tx_code.into(),
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
}
