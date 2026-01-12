use std::collections::HashMap;
use std::sync::Arc;

use dto::{
    FormattedCredentialPresentation, InvitationResponseDTO, PresentationDefinitionResponseDTO,
    ShareResponse, UpdateResponse, VerificationProtocolCapabilities,
};
use error::VerificationProtocolError;
use futures::future::BoxFuture;
use serde::de::Deserialize;
use shared_types::CredentialFormat;
use standardized_types::openid4vp::PresentationFormat;
use url::Url;

use crate::config::core_config::FormatType;
use crate::model::organisation::Organisation;
use crate::model::proof::Proof;
use crate::provider::credential_formatter::model::DetailCredential;
use crate::provider::verification_protocol::dto::PresentationDefinitionV2ResponseDTO;
use crate::service::proof::dto::ShareProofRequestParamsDTO;
use crate::service::storage_proxy::StorageAccess;

pub mod dto;
pub mod error;
pub mod iso_mdl;
mod mapper;
pub mod openid4vp;

pub(crate) mod provider;
pub mod scan_to_verify;

#[cfg(test)]
mod test;

pub(crate) fn deserialize_interaction_data<DataDTO: for<'a> Deserialize<'a>>(
    data: Option<&Vec<u8>>,
) -> Result<DataDTO, VerificationProtocolError> {
    let data = data.ok_or(VerificationProtocolError::Failed(
        "interaction data is missing".to_string(),
    ))?;
    serde_json::from_slice(data).map_err(VerificationProtocolError::JsonError)
}

pub(crate) fn serialize_interaction_data<DataDTO: ?Sized + serde::Serialize>(
    dto: &DataDTO,
) -> Result<Vec<u8>, VerificationProtocolError> {
    serde_json::to_vec(&dto).map_err(VerificationProtocolError::JsonError)
}

pub(crate) type FormatMapper =
    Arc<dyn Fn(&CredentialFormat) -> Result<FormatType, VerificationProtocolError> + Send + Sync>;
pub(crate) type TypeToDescriptorMapper = Arc<
    dyn Fn(&FormatType) -> Result<HashMap<String, PresentationFormat>, VerificationProtocolError>
        + Send
        + Sync,
>;

/// This trait contains methods for exchanging credentials between holders and verifiers.
#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait VerificationProtocol: Send + Sync {
    // Holder methods:
    /// Check if the holder can handle the necessary URLs.
    fn holder_can_handle(&self, url: &Url) -> bool;

    /// For handling credential issuance and verification, this method
    /// saves the offer information coming in.
    async fn holder_handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        storage_access: &StorageAccess,
        transport: String,
    ) -> Result<InvitationResponseDTO, VerificationProtocolError>;

    /// Rejects a verifier's request for credential presentation.
    async fn holder_reject_proof(&self, proof: &Proof) -> Result<(), VerificationProtocolError>;

    /// Submits a presentation to a verifier.
    async fn holder_submit_proof(
        &self,
        proof: &Proof,
        credential_presentations: Vec<FormattedCredentialPresentation>,
    ) -> Result<UpdateResponse, VerificationProtocolError>;

    /// Takes a proof request and filters held credentials,
    /// returning those which are acceptable for the request.
    ///
    /// Storage access is needed to check held credentials.
    async fn holder_get_presentation_definition(
        &self,
        proof: &Proof,
        context: serde_json::Value,
        storage_access: &StorageAccess,
    ) -> Result<PresentationDefinitionResponseDTO, VerificationProtocolError>;

    /// Takes a proof request and filters held credentials,
    /// returning those which are acceptable for the request.
    ///
    /// V2 endpoint which is tailored towards DCQL queries rather than presentation exchange.
    ///
    /// Storage access is needed to check held credentials.
    async fn holder_get_presentation_definition_v2(
        &self,
        proof: &Proof,
        context: serde_json::Value,
        storage_access: &StorageAccess,
    ) -> Result<PresentationDefinitionV2ResponseDTO, VerificationProtocolError>;

    /// Generates QR-code content to start the proof request flow.
    async fn verifier_share_proof(
        &self,
        proof: &Proof,
        format_to_type_mapper: FormatMapper,
        type_to_descriptor: TypeToDescriptorMapper,
        on_submission_callback: Option<BoxFuture<'static, ()>>,
        params: Option<ShareProofRequestParamsDTO>,
    ) -> Result<ShareResponse, VerificationProtocolError>;

    /// Checks if the submitted presentation complies with the given proof request.
    async fn verifier_handle_proof(
        &self,
        proof: &Proof,
        submission: &[u8],
    ) -> Result<Vec<DetailCredential>, VerificationProtocolError>;

    // General methods:
    /// Called when proof needs to be retracted. Use this function for closing opened transmissions, buffers, etc.
    async fn retract_proof(&self, proof: &Proof) -> Result<(), VerificationProtocolError>;

    fn get_capabilities(&self) -> VerificationProtocolCapabilities;
}
