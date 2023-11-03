use self::dto::{InvitationType, SubmitIssuerResponse};
use crate::{
    model::{credential::Credential, did::Did, interaction::Interaction, proof::Proof},
    service::ssi_holder::dto::InvitationResponseDTO,
};

use async_trait::async_trait;
use thiserror::Error;
use url::Url;

pub mod dto;
pub(crate) mod provider;

mod mapper;
pub mod openid4vc;
pub mod procivis_temp;
#[cfg(test)]
mod test;

#[derive(Debug, Error)]
pub enum TransportProtocolError {
    #[error("Transport protocol failure: `{0}`")]
    Failed(String),
    #[error("HTTP request error: `{0}`")]
    HttpRequestError(reqwest::Error),
    #[error("HTTP response error: `{0}`")]
    HttpResponse(reqwest::Error),
    #[error("JSON error: `{0}`")]
    JsonError(serde_json::Error),
    #[error("Operation not supported")]
    OperationNotSupported,
    #[error("Base url is unknown")]
    MissingBaseUrl,
}

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait TransportProtocol {
    // holder methods
    fn detect_invitation_type(&self, url: &Url) -> Option<InvitationType>;

    async fn handle_invitation(
        &self,
        url: Url,
        own_did: Did,
    ) -> Result<InvitationResponseDTO, TransportProtocolError>;

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

pub(super) fn get_base_url_from_interaction(
    interaction: Option<&Interaction>,
) -> Result<Url, TransportProtocolError> {
    interaction
        .ok_or(TransportProtocolError::Failed(
            "interaction is None".to_string(),
        ))?
        .host
        .as_ref()
        .ok_or(TransportProtocolError::Failed(
            "interaction host is missing".to_string(),
        ))
        .cloned()
}
