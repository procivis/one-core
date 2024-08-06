use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use dto::ScanToVerifyCredentialDTO;
use one_providers::common_dto::PublicKeyJwkDTO;
use one_providers::common_models::credential::Credential;
use one_providers::common_models::did::{Did, KeyRole};
use one_providers::common_models::key::{Key, KeyId};
use one_providers::common_models::organisation::Organisation;
use one_providers::common_models::proof::Proof;
use one_providers::credential_formatter::model::DetailCredential;
use one_providers::credential_formatter::provider::CredentialFormatterProvider;
use one_providers::did::provider::DidMethodProvider;
use one_providers::exchange_protocol::openid4vc::model::{
    DatatypeType, InvitationResponseDTO, OpenID4VPFormat, PresentationDefinitionResponseDTO,
    PresentedCredential, ShareResponse, SubmitIssuerResponse, UpdateResponse,
};
use one_providers::exchange_protocol::openid4vc::{
    ExchangeProtocolError, ExchangeProtocolImpl, FormatMapper, HandleInvitationOperationsAccess,
    StorageAccess, TypeToDescriptorMapper,
};
use one_providers::key_algorithm::provider::KeyAlgorithmProvider;
use url::Url;

use crate::service::proof::dto::ScanToVerifyRequestDTO;
use crate::util::key_verification::KeyVerification;

pub mod dto;

pub(crate) struct ScanToVerify {
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
}

impl ScanToVerify {
    pub fn new(
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
impl ExchangeProtocolImpl for ScanToVerify {
    type VCInteractionContext = ();
    type VPInteractionContext = ();

    fn can_handle(&self, _url: &Url) -> bool {
        false
    }

    async fn handle_invitation(
        &self,
        _url: Url,
        _storage_access: &StorageAccess,
        _handle_invitation_operations: &HandleInvitationOperationsAccess,
    ) -> Result<InvitationResponseDTO, ExchangeProtocolError> {
        unimplemented!()
    }

    async fn reject_proof(&self, _proof: &Proof) -> Result<(), ExchangeProtocolError> {
        unimplemented!()
    }

    async fn submit_proof(
        &self,
        _proof: &Proof,
        _credential_presentations: Vec<PresentedCredential>,
        _holder_did: &Did,
        _key: &Key,
        _jwk_key_id: Option<String>,
        _format_map: HashMap<String, String>,
        _presentation_format_map: HashMap<String, String>,
    ) -> Result<UpdateResponse<()>, ExchangeProtocolError> {
        unimplemented!()
    }

    async fn accept_credential(
        &self,
        _credential: &Credential,
        _holder_did: &Did,
        _key: &Key,
        _jwk_key_id: Option<String>,
        _format: &str,
        _storage_access: &StorageAccess,
    ) -> Result<UpdateResponse<SubmitIssuerResponse>, ExchangeProtocolError> {
        unimplemented!()
    }

    async fn reject_credential(
        &self,
        _credential: &Credential,
    ) -> Result<(), ExchangeProtocolError> {
        unimplemented!()
    }

    async fn share_credential(
        &self,
        _credential: &Credential,
        _credential_format: &str,
    ) -> Result<ShareResponse<Self::VCInteractionContext>, ExchangeProtocolError> {
        unimplemented!()
    }

    async fn share_proof(
        &self,
        _proof: &Proof,
        _format_to_type_mapper: FormatMapper,
        _key_id: KeyId,
        _encryption_key_jwk: PublicKeyJwkDTO,
        _vp_formats: HashMap<String, OpenID4VPFormat>,
        _type_to_descriptor: TypeToDescriptorMapper,
    ) -> Result<ShareResponse<Self::VPInteractionContext>, ExchangeProtocolError> {
        unimplemented!()
    }

    async fn get_presentation_definition(
        &self,
        _proof: &Proof,
        _interaction_data: Self::VPInteractionContext,
        _storage_access: &StorageAccess,
        _format_map: HashMap<String, String>,
        _types: HashMap<String, DatatypeType>,
        _organisation: Organisation,
    ) -> Result<PresentationDefinitionResponseDTO, ExchangeProtocolError> {
        unimplemented!()
    }

    async fn verifier_handle_proof(
        &self,
        proof: &Proof,
        submission: &[u8],
    ) -> Result<Vec<DetailCredential>, ExchangeProtocolError> {
        let proof_schema = proof.schema.as_ref().ok_or(ExchangeProtocolError::Failed(
            "proof_schema is None".to_string(),
        ))?;

        let input_schema = proof_schema
            .input_schemas
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed(
                "input_schemas is None".to_string(),
            ))?
            .first() // always 1 credential is requested during SCAN_TO_VERIFY
            .ok_or(ExchangeProtocolError::Failed(
                "input_schemas is empty".to_string(),
            ))?;

        let credential_schema =
            input_schema
                .credential_schema
                .as_ref()
                .ok_or(ExchangeProtocolError::Failed(
                    "credential_schema is None".to_string(),
                ))?;

        let formatter = self
            .formatter_provider
            .get_formatter(&credential_schema.format)
            .ok_or_else(|| ExchangeProtocolError::Failed("Formatter not found".to_string()))?;

        let request: ScanToVerifyRequestDTO =
            serde_json::from_slice(submission).map_err(ExchangeProtocolError::JsonError)?;

        let credentials = serde_json::to_string(&ScanToVerifyCredentialDTO {
            schema_id: credential_schema.schema_id.to_owned(),
            credential: request.credential,
            barcode: request.barcode,
        })
        .map_err(ExchangeProtocolError::JsonError)?;

        let key_verification = Box::new(KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::AssertionMethod.into(),
        });

        let credential = formatter
            .extract_credentials(&credentials, key_verification)
            .await
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        Ok(vec![credential])
    }
}
