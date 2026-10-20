use std::fmt::Display;
use std::sync::Arc;

use futures::future::BoxFuture;
use url::Url;

use super::dto::{
    FormattedCredentialPresentation, InvitationResponseDTO, PresentationDefinitionV2ResponseDTO,
    UpdateResponse, VerificationProtocolCapabilities,
};
use super::error::VerificationProtocolError;
use super::{ShareResponse, VerificationProtocol};
use crate::model::identifier::IdentifierData;
use crate::model::organisation::Organisation;
use crate::model::proof::Proof;
use crate::provider::Provider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::disabled_provider::DisabledProvider;
use crate::provider::provider_directory::WithDisabledDecorator;
use crate::provider::verification_protocol::dto::PresentationDefinitionVersion;
use crate::service::proof::dto::ShareProofRequestParamsDTO;

impl WithDisabledDecorator for dyn VerificationProtocol {
    fn decorate(self: Arc<dyn VerificationProtocol>) -> Arc<dyn VerificationProtocol> {
        Arc::new(DisabledProvider::new(self))
    }
}

#[async_trait::async_trait]
impl<T: Provider + VerificationProtocol + Display + ?Sized> VerificationProtocol
    for DisabledProvider<T>
{
    fn holder_can_handle(&self, _url: &Url) -> bool {
        false
    }

    async fn holder_handle_invitation<'a>(
        &self,
        _url: Url,
        _organisation: Organisation,
        _transport: String,
    ) -> Result<InvitationResponseDTO<'a>, VerificationProtocolError> {
        self.disabled_error()
    }

    async fn holder_reject_proof(&self, _proof: &Proof) -> Result<(), VerificationProtocolError> {
        self.disabled_error()
    }

    async fn holder_submit_proof(
        &self,
        _proof: &Proof,
        _credential_presentations: Vec<FormattedCredentialPresentation>,
    ) -> Result<UpdateResponse, VerificationProtocolError> {
        self.disabled_error()
    }

    async fn holder_get_presentation_definition_v2(
        &self,
        _proof: &Proof,
        _submitted_credential_ids: &[shared_types::CredentialId],
    ) -> Result<PresentationDefinitionV2ResponseDTO, VerificationProtocolError> {
        self.disabled_error()
    }

    async fn verifier_share_proof(
        &self,
        _proof: &Proof,
        _on_submission_callback: Option<BoxFuture<'static, ()>>,
        _params: Option<ShareProofRequestParamsDTO>,
    ) -> Result<ShareResponse, VerificationProtocolError> {
        self.disabled_error()
    }

    async fn retract_proof(&self, proof: &Proof) -> Result<(), VerificationProtocolError> {
        self.inner().retract_proof(proof).await
    }

    fn get_capabilities(&self) -> VerificationProtocolCapabilities {
        self.inner().get_capabilities()
    }

    fn config_name(&self) -> &str {
        self.inner().config_name()
    }
}

/// Checks supported operations
pub(super) struct CapabilityChecked {
    pub inner: Arc<dyn VerificationProtocol>,
    pub did_method_provider: Arc<dyn DidMethodProvider>,
}

impl Provider for CapabilityChecked {
    fn capabilities(&self) -> Option<serde_json::Value> {
        self.inner.capabilities()
    }
}

#[async_trait::async_trait]
impl VerificationProtocol for CapabilityChecked {
    fn holder_can_handle(&self, url: &Url) -> bool {
        self.inner.holder_can_handle(url)
    }

    async fn holder_handle_invitation<'a>(
        &self,
        url: Url,
        organisation: Organisation,
        transport: String,
    ) -> Result<InvitationResponseDTO<'a>, VerificationProtocolError> {
        self.inner
            .holder_handle_invitation(url, organisation, transport)
            .await
    }

    async fn holder_reject_proof(&self, proof: &Proof) -> Result<(), VerificationProtocolError> {
        self.inner.holder_reject_proof(proof).await
    }

    async fn holder_submit_proof(
        &self,
        proof: &Proof,
        credential_presentations: Vec<FormattedCredentialPresentation>,
    ) -> Result<UpdateResponse, VerificationProtocolError> {
        self.inner
            .holder_submit_proof(proof, credential_presentations)
            .await
    }

    async fn holder_get_presentation_definition_v2(
        &self,
        proof: &Proof,
        submitted_credential_ids: &[shared_types::CredentialId],
    ) -> Result<PresentationDefinitionV2ResponseDTO, VerificationProtocolError> {
        let capabilities = self.inner.get_capabilities();
        if !capabilities
            .supported_presentation_definition
            .contains(&PresentationDefinitionVersion::V2)
        {
            return Err(VerificationProtocolError::OperationNotSupported);
        }

        self.inner
            .holder_get_presentation_definition_v2(proof, submitted_credential_ids)
            .await
    }

    async fn verifier_share_proof(
        &self,
        proof: &Proof,
        on_submission_callback: Option<BoxFuture<'static, ()>>,
        params: Option<ShareProofRequestParamsDTO>,
    ) -> Result<ShareResponse, VerificationProtocolError> {
        let capabilities = self.inner.get_capabilities();

        let verifier_identifier = proof
            .verifier_identifier
            .as_ref()
            .ok_or(VerificationProtocolError::Failed(
                "Missing verifier identifier".to_string(),
            ))?
            .as_ref()
            .await?;
        if !capabilities
            .verifier_identifier_types
            .contains(&verifier_identifier.data.r#type().into())
        {
            return Err(VerificationProtocolError::Failed(format!(
                "Invalid verifier identifier type: {}",
                verifier_identifier.data.r#type()
            )));
        }

        if let IdentifierData::Did(verifier_did) = &verifier_identifier.data {
            let verifier_did = verifier_did.as_ref().await?;
            let (_, did_type) = self
                .did_method_provider
                .get_did_method(&verifier_did.did_method)?;
            if !capabilities.did_methods.contains(&did_type) {
                return Err(VerificationProtocolError::Failed(format!(
                    "Invalid verifier DID method: {}",
                    verifier_did.did_method
                )));
            }
        }

        self.inner
            .verifier_share_proof(proof, on_submission_callback, params)
            .await
    }

    async fn retract_proof(&self, proof: &Proof) -> Result<(), VerificationProtocolError> {
        self.inner.retract_proof(proof).await
    }

    fn get_capabilities(&self) -> VerificationProtocolCapabilities {
        self.inner.get_capabilities()
    }

    fn config_name(&self) -> &str {
        self.inner.config_name()
    }
}
