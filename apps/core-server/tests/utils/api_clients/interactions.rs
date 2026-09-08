use serde_json::json;
use shared_types::{CredentialId, DidId, InstanceId, KeyId, OrganisationId};
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
        did_id: impl Into<Option<DidId>>,
        key_id: impl Into<Option<KeyId>>,
        tx_code: impl Into<Option<&str>>,
        holder_wallet_unit_id: impl Into<Option<InstanceId>>,
    ) -> Response {
        let body = json!({
          "interactionId": interaction_id.into(),
          "didId": did_id.into(),
          "keyId": key_id.into(),
          "txCode": tx_code.into(),
          "holderWalletUnitId": holder_wallet_unit_id.into(),
        });

        self.client
            .post("/api/interaction/v1/issuance-accept", body)
            .await
    }

    pub async fn issuance_reject(
        &self,
        interaction_id: impl Into<Uuid>,
        credential_ids: Option<Vec<CredentialId>>,
    ) -> Response {
        let body = json!({
          "interactionId": interaction_id.into(),
          "credentialIds": credential_ids,
        });

        self.client
            .post("/api/interaction/v1/issuance-reject", body)
            .await
    }

    pub async fn issuance_refresh(&self, interaction_id: impl Into<Uuid>) -> Response {
        let url = format!(
            "/api/interaction/v1/{}/issuance-refresh",
            interaction_id.into(),
        );
        self.client.post(&url, None).await
    }

    pub async fn initiate_issuance(
        &self,
        organisation_id: impl Into<Uuid>,
        protocol: impl Into<String>,
        client_id: impl Into<String>,
        issuer: impl Into<String>,
        scope: impl Into<Vec<String>>,
    ) -> Response {
        let body = json!({
          "organisationId": organisation_id.into(),
          "protocol": protocol.into(),
          "clientId": client_id.into(),
          "issuer": issuer.into(),
          "scope": scope.into(),
        });

        self.client
            .post("/api/interaction/v1/initiate-issuance", body)
            .await
    }

    pub async fn continue_issuance(&self, url: impl Into<String>) -> Response {
        let body = json!({
          "url": url.into(),
        });

        self.client
            .post("/api/interaction/v1/continue-issuance", body)
            .await
    }

    pub async fn presentation_submit_v2(
        &self,
        interaction_id: impl Into<Uuid>,
        credential_id: impl Into<Uuid>,
        user_selections: &[&str],
        transaction_data_ids: &[Uuid],
    ) -> Response {
        let mut body = json!({
          "interactionId": interaction_id.into(),
          "submission": {
            "input_0": {
              "credentialId": credential_id.into(),
            }
          }
        });
        if !user_selections.is_empty() {
            body["submission"]["input_0"]["userSelections"] = json!(user_selections);
        }
        if !transaction_data_ids.is_empty() {
            body["submission"]["input_0"]["transactionDataIds"] = json!(transaction_data_ids);
        }
        self.client
            .post("/api/interaction/v2/presentation-submit", body)
            .await
    }
}
