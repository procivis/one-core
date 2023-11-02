use super::{
    dto::{InvitationResponse, InvitationType, SubmitIssuerResponse},
    TransportProtocol, TransportProtocolError,
};
use crate::model::{credential::Credential, did::Did, proof::Proof};
use crate::util::oidc::map_core_to_oidc_format;
use dto::{OpenID4VCICredentialDefinition, OpenID4VCICredentialRequestRestDTO};

use async_trait::async_trait;
use serde_json::json;

pub mod dto;

pub struct OpenID4VC {
    client: reqwest::Client,
}

impl Default for OpenID4VC {
    fn default() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl TransportProtocol for OpenID4VC {
    fn detect_invitation_type(&self, _url: &str) -> Option<InvitationType> {
        unimplemented!()
    }

    async fn handle_invitation(
        &self,
        _url: &str,
        _own_did: &Did,
    ) -> Result<InvitationResponse, TransportProtocolError> {
        unimplemented!()
    }

    async fn reject_proof(&self, _proof: &Proof) -> Result<(), TransportProtocolError> {
        unimplemented!()
    }

    async fn submit_proof(
        &self,
        _proof: &Proof,
        _presentation: &str,
    ) -> Result<(), TransportProtocolError> {
        unimplemented!()
    }

    async fn accept_credential(
        &self,
        credential: &Credential,
    ) -> Result<SubmitIssuerResponse, TransportProtocolError> {
        let schema = credential
            .schema
            .as_ref()
            .ok_or(TransportProtocolError::Failed("schema is None".to_string()))?;

        let format = map_core_to_oidc_format(&schema.format)
            .map_err(|e| TransportProtocolError::Failed(e.to_string()))?;
        let schema_id = schema.id.to_string();

        let body = OpenID4VCICredentialRequestRestDTO {
            format,
            credential_definition: OpenID4VCICredentialDefinition {
                r#type: vec!["VerifiableCredential".to_string()],
            },
        };

        let mut url = super::get_base_url(&credential.interaction)?;
        url.set_path(&format!("/ssi/oidc-issuer/v1/{}/credential", schema_id));

        let response = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .body(json!(body).to_string())
            .send()
            .await
            .map_err(TransportProtocolError::HttpRequestError)?;
        let response = response
            .error_for_status()
            .map_err(TransportProtocolError::HttpRequestError)?;
        let response_value = response
            .text()
            .await
            .map_err(TransportProtocolError::HttpRequestError)?;

        serde_json::from_str(&response_value).map_err(TransportProtocolError::JsonError)
    }

    async fn reject_credential(
        &self,
        _credential: &Credential,
    ) -> Result<(), TransportProtocolError> {
        Err(TransportProtocolError::OperationNotSupported)
    }

    async fn share_credential(
        &self,
        _credential: &Credential,
    ) -> Result<String, TransportProtocolError> {
        unimplemented!()
    }

    async fn share_proof(&self, _proof: &Proof) -> Result<String, TransportProtocolError> {
        unimplemented!()
    }
}
