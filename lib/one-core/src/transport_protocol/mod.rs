use crate::data_model::{ConnectIssuerResponse, ConnectVerifierResponse};
use async_trait::async_trait;

use thiserror::Error;

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

#[derive(Clone)]
pub enum InvitationResponse {
    Credential(ConnectIssuerResponse),
    Proof(ConnectVerifierResponse),
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
}
