use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use dto::ScanToVerifyCredentialDTO;
use futures::future::BoxFuture;
use shared_types::KeyId;
use url::Url;

use super::dto::{
    InvitationResponseDTO, PresentationDefinitionResponseDTO, PresentedCredential, ShareResponse,
    UpdateResponse, VerificationProtocolCapabilities,
};
use super::{
    FormatMapper, StorageAccess, TypeToDescriptorMapper, VerificationProtocol,
    VerificationProtocolError,
};
use crate::config::core_config::{DidType, TransportType};
use crate::model::did::{Did, KeyRole};
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::proof::Proof;
use crate::provider::credential_formatter::model::{DetailCredential, HolderBindingCtx};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::verification_protocol::openid4vp::model::OpenID4VpPresentationFormat;
use crate::service::key::dto::PublicKeyJwkDTO;
use crate::service::proof::dto::{ScanToVerifyRequestDTO, ShareProofRequestParamsDTO};
use crate::util::key_verification::KeyVerification;

pub mod dto;

pub(crate) struct ScanToVerify {
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
}

impl ScanToVerify {
    pub(crate) fn new(
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
    ) -> Self {
        Self {
            formatter_provider,
            key_algorithm_provider,
            did_method_provider,
        }
    }
}

#[async_trait]
impl VerificationProtocol for ScanToVerify {
    fn holder_can_handle(&self, _url: &Url) -> bool {
        false
    }
    fn holder_get_holder_binding_context(
        &self,
        _proof: &Proof,
        _context: serde_json::Value,
    ) -> Result<Option<HolderBindingCtx>, VerificationProtocolError> {
        Ok(None)
    }

    async fn holder_handle_invitation(
        &self,
        _url: Url,
        _organisation: Organisation,
        _storage_access: &StorageAccess,
        _transport: String,
    ) -> Result<InvitationResponseDTO, VerificationProtocolError> {
        unimplemented!()
    }

    async fn holder_reject_proof(&self, _proof: &Proof) -> Result<(), VerificationProtocolError> {
        unimplemented!()
    }

    async fn holder_submit_proof(
        &self,
        _proof: &Proof,
        _credential_presentations: Vec<PresentedCredential>,
        _holder_did: &Did,
        _key: &Key,
        _jwk_key_id: Option<String>,
    ) -> Result<UpdateResponse, VerificationProtocolError> {
        unimplemented!()
    }

    async fn holder_get_presentation_definition(
        &self,
        _proof: &Proof,
        _interaction_data: serde_json::Value,
        _storage_access: &StorageAccess,
    ) -> Result<PresentationDefinitionResponseDTO, VerificationProtocolError> {
        unimplemented!()
    }

    async fn retract_proof(&self, _proof: &Proof) -> Result<(), VerificationProtocolError> {
        Ok(())
    }

    async fn verifier_share_proof(
        &self,
        _proof: &Proof,
        _format_to_type_mapper: FormatMapper,
        _key_id: KeyId,
        _encryption_key_jwk: PublicKeyJwkDTO,
        _vp_formats: HashMap<String, OpenID4VpPresentationFormat>,
        _type_to_descriptor: TypeToDescriptorMapper,
        _callback: Option<BoxFuture<'static, ()>>,
        _params: Option<ShareProofRequestParamsDTO>,
    ) -> Result<ShareResponse<serde_json::Value>, VerificationProtocolError> {
        unimplemented!()
    }

    async fn verifier_handle_proof(
        &self,
        proof: &Proof,
        submission: &[u8],
    ) -> Result<Vec<DetailCredential>, VerificationProtocolError> {
        let proof_schema = proof
            .schema
            .as_ref()
            .ok_or(VerificationProtocolError::Failed(
                "proof_schema is None".to_string(),
            ))?;

        let input_schema = proof_schema
            .input_schemas
            .as_ref()
            .ok_or(VerificationProtocolError::Failed(
                "input_schemas is None".to_string(),
            ))?
            .first() // always 1 credential is requested during SCAN_TO_VERIFY
            .ok_or(VerificationProtocolError::Failed(
                "input_schemas is empty".to_string(),
            ))?;

        let credential_schema =
            input_schema
                .credential_schema
                .as_ref()
                .ok_or(VerificationProtocolError::Failed(
                    "credential_schema is None".to_string(),
                ))?;

        let formatter = self
            .formatter_provider
            .get_formatter(&credential_schema.format)
            .ok_or_else(|| VerificationProtocolError::Failed("Formatter not found".to_string()))?;

        let request: ScanToVerifyRequestDTO =
            serde_json::from_slice(submission).map_err(VerificationProtocolError::JsonError)?;

        let credentials = serde_json::to_string(&ScanToVerifyCredentialDTO {
            schema_id: credential_schema.schema_id.to_owned(),
            credential: request.credential,
            barcode: request.barcode,
        })
        .map_err(VerificationProtocolError::JsonError)?;

        let key_verification = Box::new(KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::AssertionMethod,
        });

        let credential = formatter
            .extract_credentials(&credentials, key_verification, None)
            .await
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        Ok(vec![credential])
    }

    fn get_capabilities(&self) -> VerificationProtocolCapabilities {
        VerificationProtocolCapabilities {
            supported_transports: vec![TransportType::Http],
            did_methods: vec![
                DidType::Key,
                DidType::Jwk,
                DidType::Web,
                DidType::MDL,
                DidType::WebVh,
            ],
        }
    }
}
