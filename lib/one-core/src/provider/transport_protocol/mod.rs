use self::dto::{InvitationResponse, InvitationType, SubmitIssuerResponse};
use crate::model::{credential::Credential, did::Did, proof::Proof};
use async_trait::async_trait;
use thiserror::Error;

pub mod dto;
pub(crate) mod provider;

pub mod openid4vc;
pub mod procivis_temp;

#[derive(Debug, Error)]
pub enum TransportProtocolError {
    #[error("Transport protocol failure: `{0}`")]
    Failed(String),
    #[error("HTTP request error: `{0}`")]
    HttpRequestError(reqwest::Error),
    #[error("JSON error: `{0}`")]
    JsonError(serde_json::Error),
    #[error("Operation not supported")]
    OperationNotSupported,
}

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait TransportProtocol {
    // holder methods
    fn detect_invitation_type(&self, url: &str) -> Option<InvitationType>;

    async fn handle_invitation(
        &self,
        url: &str,
        own_did: &Did,
    ) -> Result<InvitationResponse, TransportProtocolError>;

    async fn reject_proof(&self, proof: &Proof) -> Result<(), TransportProtocolError>;

    async fn submit_proof(
        &self,
        proof: &Proof,
        presentation: &str,
    ) -> Result<(), TransportProtocolError>;

    async fn accept_credential(
        &self,
        credential: &Credential,
    ) -> Result<SubmitIssuerResponse, TransportProtocolError>;

    async fn reject_credential(
        &self,
        credential: &Credential,
    ) -> Result<(), TransportProtocolError>;

    // issuer methods
    /// Generates QR-code content to start the credential issuance flow
    async fn share_credential(
        &self,
        credential: &Credential,
    ) -> Result<String, TransportProtocolError>;

    // verifier methods
    /// Generates QR-code content to start the proof request flow
    async fn share_proof(&self, proof: &Proof) -> Result<String, TransportProtocolError>;
}
