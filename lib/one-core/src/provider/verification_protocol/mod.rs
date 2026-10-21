use std::fmt::{Display, Formatter};

use dto::{
    FormattedCredentialPresentation, InvitationRequest, InvitationResponseDTO,
    PresentationDefinitionV2ResponseDTO, ShareResponse, VerificationProtocolCapabilities,
};
use error::VerificationProtocolError;
use futures::future::BoxFuture;
use proc_macros::provider_mock;
use serde::de::Deserialize;
use shared_types::CredentialId;

use crate::model::organisation::Organisation;
use crate::model::proof::Proof;
use crate::provider::Provider;
use crate::service::proof::dto::ShareProofRequestParamsDTO;

mod decorators;
pub mod dto;
pub mod error;
pub mod iso_mdl;
mod mapper;
pub(crate) mod model;
pub mod openid4vp;

pub(crate) mod provider;

pub(crate) fn deserialize_interaction_data<DataDTO: for<'a> Deserialize<'a>>(
    data: Option<&Vec<u8>>,
) -> Result<DataDTO, VerificationProtocolError> {
    let data = data.ok_or(VerificationProtocolError::Failed(
        "interaction data is missing".to_string(),
    ))?;
    Ok(serde_json::from_slice(data)?)
}

pub(crate) fn serialize_interaction_data<DataDTO: ?Sized + serde::Serialize>(
    dto: &DataDTO,
) -> Result<Vec<u8>, VerificationProtocolError> {
    Ok(serde_json::to_vec(&dto)?)
}

/// This trait contains methods for exchanging credentials between holders and verifiers.
#[provider_mock]
#[async_trait::async_trait]
pub(crate) trait VerificationProtocol: Provider + Send + Sync {
    // Holder methods:
    /// Check if the holder can handle the proof request invitation.
    fn holder_can_handle(&self, request: &InvitationRequest) -> bool;

    /// For handling credential presentation, creates a new proof with holder role
    async fn holder_handle_invitation<'a>(
        &self,
        request: InvitationRequest,
        organisation: Organisation,
        transport: String,
    ) -> Result<InvitationResponseDTO<'a>, VerificationProtocolError>;

    /// Rejects a verifier's request for credential presentation.
    async fn holder_reject_proof(&self, proof: &Proof) -> Result<(), VerificationProtocolError>;

    /// Submits a presentation to a verifier.
    async fn holder_submit_proof(
        &self,
        proof: &Proof,
        credential_presentations: Vec<FormattedCredentialPresentation>,
    ) -> Result<(), VerificationProtocolError>;

    /// Takes a proof request and filters held credentials,
    /// returning those which are acceptable for the request.
    ///
    /// V2 endpoint which is tailored towards DCQL queries rather than presentation exchange.
    ///
    /// On submission, pass the selected IDs to check any explicitly selected batch items
    /// and identify matching but unavailable items for exhausted-batch errors.
    /// Pass an empty slice for definition requests.
    async fn holder_get_presentation_definition_v2(
        &self,
        proof: &Proof,
        submitted_credential_ids: &[CredentialId],
    ) -> Result<PresentationDefinitionV2ResponseDTO, VerificationProtocolError>;

    /// Generates QR-code content to start the proof request flow.
    async fn verifier_share_proof(
        &self,
        proof: &Proof,
        on_submission_callback: Option<BoxFuture<'static, ()>>,
        params: Option<ShareProofRequestParamsDTO>,
    ) -> Result<ShareResponse, VerificationProtocolError>;

    // General methods:
    /// Called when proof needs to be retracted. Use this function for closing opened transmissions, buffers, etc.
    async fn retract_proof(&self, proof: &Proof) -> Result<(), VerificationProtocolError>;

    fn get_capabilities(&self) -> VerificationProtocolCapabilities;

    fn config_name(&self) -> &str;
}

impl Display for dyn VerificationProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Verification protocol `{}`", self.config_name())
    }
}
