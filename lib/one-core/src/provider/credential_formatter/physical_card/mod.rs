use std::sync::Arc;
use std::vec;

use async_trait::async_trait;
use model::OptiocalBarcodeCredential;
use one_crypto::CryptoProvider;
use shared_types::CredentialSchemaId;

use super::json_ld_classic::verify_credential_signature;
use super::model::{CredentialData, HolderBindingCtx};
use crate::config::core_config::{
    DidType, IdentifierType, KeyAlgorithmType, KeyStorageType, RevocationType,
    VerificationProtocolType,
};
use crate::model::credential::Credential;
use crate::model::credential_schema::CredentialSchema;
use crate::model::identifier::Identifier;
use crate::proto::http_client::HttpClient;
use crate::provider::caching_loader::json_ld_context::{ContextCache, JsonLdCachingLoader};
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{
    AuthenticationFn, CredentialPresentation, DetailCredential, Features, FormatterCapabilities,
    VerificationFn,
};
use crate::provider::credential_formatter::{CredentialFormatter, MetadataClaimSchema};
use crate::provider::revocation::bitstring_status_list::model::StatusPurpose;
use crate::service::credential_schema::dto::CreateCredentialSchemaRequestDTO;

mod mappers;
mod model;

pub struct PhysicalCardFormatter {
    pub crypto: Arc<dyn CryptoProvider>,
    pub caching_loader: ContextCache,
}

#[cfg(test)]
mod test;

#[async_trait]
impl CredentialFormatter for PhysicalCardFormatter {
    async fn format_credential(
        &self,
        _credential_data: CredentialData,
        _auth_fn: AuthenticationFn,
    ) -> Result<String, FormatterError> {
        todo!()
    }

    async fn format_status_list(
        &self,
        _revocation_list_url: String,
        _issuer_identifier: &Identifier,
        _encoded_list: String,
        _algorithm: KeyAlgorithmType,
        _auth_fn: AuthenticationFn,
        _status_purpose: StatusPurpose,
        _status_list_type: RevocationType,
    ) -> Result<String, FormatterError> {
        Err(FormatterError::Failed(
            "Cannot format StatusList with PhysicalCard formatter".to_string(),
        ))
    }

    async fn extract_credentials<'a>(
        &self,
        token: &str,
        _credential_schema: Option<&'a CredentialSchema>,
        verification_fn: VerificationFn,
        _holder_binding_ctx: Option<HolderBindingCtx>,
    ) -> Result<DetailCredential, FormatterError> {
        let credential_with_optical_data = OptiocalBarcodeCredential::from_token(token)?;
        let extra_information_for_proof = credential_with_optical_data.extra_information_bytes();

        verify_credential_signature(
            credential_with_optical_data.credential.clone(),
            verification_fn,
            &*self.crypto,
            self.caching_loader.clone(),
            Some(&extra_information_for_proof?),
        )
        .await?;

        credential_with_optical_data.try_into()
    }

    async fn extract_credentials_unverified<'a>(
        &self,
        token: &str,
        _credential_schema: Option<&'a CredentialSchema>,
    ) -> Result<DetailCredential, FormatterError> {
        OptiocalBarcodeCredential::from_token(token)?.try_into()
    }

    async fn prepare_selective_disclosure(
        &self,
        _credential: CredentialPresentation,
    ) -> Result<String, FormatterError> {
        todo!()
    }

    fn get_leeway(&self) -> u64 {
        todo!()
    }

    fn get_capabilities(&self) -> FormatterCapabilities {
        FormatterCapabilities {
            signing_key_algorithms: vec![
                KeyAlgorithmType::Eddsa,
                KeyAlgorithmType::Ecdsa,
                KeyAlgorithmType::MlDsa,
            ],
            allowed_schema_ids: vec![
                "UtopiaEmploymentDocument".to_string(),
                "UtopiaDrivingLicense".to_string(),
                "IdentityCard".to_string(),
            ],
            ecosystem_schema_ids: vec![],
            features: vec![Features::SupportsSchemaId],
            selective_disclosure: vec![],
            issuance_did_methods: vec![],
            issuance_exchange_protocols: vec![],
            proof_exchange_protocols: vec![VerificationProtocolType::ScanToVerify],
            revocation_methods: vec![RevocationType::None],
            verification_key_algorithms: vec![
                KeyAlgorithmType::Eddsa,
                KeyAlgorithmType::Ecdsa,
                KeyAlgorithmType::MlDsa,
            ],
            verification_key_storages: vec![
                KeyStorageType::Internal,
                KeyStorageType::AzureVault,
                KeyStorageType::SecureElement,
            ],
            datatypes: vec![
                "STRING".to_string(),
                "EMAIL".to_string(),
                "DATE".to_string(),
                "STRING".to_string(),
                "COUNT".to_string(),
                "BIRTH_DATE".to_string(),
                "NUMBER".to_string(),
            ],
            forbidden_claim_names: vec![],
            issuance_identifier_types: vec![IdentifierType::Did],
            verification_identifier_types: vec![IdentifierType::Did, IdentifierType::Certificate],
            holder_identifier_types: vec![IdentifierType::Did],
            holder_key_algorithms: vec![
                KeyAlgorithmType::Ecdsa,
                KeyAlgorithmType::Eddsa,
                KeyAlgorithmType::MlDsa,
            ],
            holder_did_methods: vec![DidType::Web, DidType::Key, DidType::Jwk, DidType::WebVh],
        }
    }

    fn credential_schema_id(
        &self,
        _id: CredentialSchemaId,
        request: &CreateCredentialSchemaRequestDTO,
        _core_base_url: &str,
    ) -> Result<String, FormatterError> {
        Ok(request
            .schema_id
            .as_ref()
            .ok_or(FormatterError::Failed(
                "No schema_id specified for PHYSICAL_CARD".to_string(),
            ))?
            .to_owned())
    }

    fn get_metadata_claims(&self) -> Vec<MetadataClaimSchema> {
        vec![]
    }

    fn user_claims_path(&self) -> Vec<String> {
        vec![]
    }

    async fn parse_credential(&self, _credential: &str) -> Result<Credential, FormatterError> {
        unimplemented!()
    }
}

impl PhysicalCardFormatter {
    pub fn new(
        crypto: Arc<dyn CryptoProvider>,
        caching_loader: JsonLdCachingLoader,
        client: Arc<dyn HttpClient>,
    ) -> Self {
        Self {
            crypto,
            caching_loader: ContextCache::new(caching_loader, client),
        }
    }
}
