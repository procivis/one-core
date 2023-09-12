use self::dto::InvitationResponse;
use async_trait::async_trait;
use thiserror::Error;

pub mod dto;
pub(crate) mod provider;

pub mod procivis_temp;

#[derive(Debug, Error)]
pub enum TransportProtocolError {
    #[error("Transport protocol failure: `{0}`")]
    Failed(String),
    #[error("HTTP request error: `{0}`")]
    HttpRequestError(reqwest::Error),
    #[error("JSON error: `{0}`")]
    JsonError(serde_json::Error),
}

// This is just a proposition.
// Will be  developed in future.
#[async_trait]
pub trait TransportProtocol {
    async fn handle_invitation(
        &self,
        url: &str,
        own_did: &str,
    ) -> Result<InvitationResponse, TransportProtocolError>;

    async fn reject_proof(
        &self,
        base_url: &str,
        proof_id: &str,
    ) -> Result<(), TransportProtocolError>;

    async fn submit_proof(
        &self,
        base_url: &str,
        proof_id: &str,
        presentation: &str,
    ) -> Result<(), TransportProtocolError>;
}
