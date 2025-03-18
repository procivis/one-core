use std::sync::Arc;
use std::vec;

use async_trait::async_trait;
use model::OptiocalBarcodeCredential;
use one_crypto::CryptoProvider;
use shared_types::{CredentialSchemaId, DidValue};

use super::json_ld_classic::verify_credential_signature;
use super::model::{CredentialData, HolderBindingCtx};
use crate::config::core_config::{ExchangeType, KeyStorageType, RevocationType};
use crate::model::did::Did;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::json_ld::context::caching_loader::{
    ContextCache, JsonLdCachingLoader,
};
use crate::provider::credential_formatter::model::{
    AuthenticationFn, CredentialPresentation, DetailCredential, ExtractPresentationCtx, Features,
    FormatPresentationCtx, FormatterCapabilities, Presentation, VerificationFn,
};
use crate::provider::credential_formatter::{CredentialFormatter, StatusListType};
use crate::provider::http_client::HttpClient;
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
        _issuer_did: &Did,
        _encoded_list: String,
        _algorithm: String,
        _auth_fn: AuthenticationFn,
        _status_purpose: StatusPurpose,
        _status_list_type: StatusListType,
    ) -> Result<String, FormatterError> {
        Err(FormatterError::Failed(
            "Cannot format StatusList with PhysicalCard formatter".to_string(),
        ))
    }

    async fn extract_credentials(
        &self,
        token: &str,
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

    async fn extract_credentials_unverified(
        &self,
        token: &str,
    ) -> Result<DetailCredential, FormatterError> {
        OptiocalBarcodeCredential::from_token(token)?.try_into()
    }

    async fn format_presentation(
        &self,
        _credentials: &[String],
        _holder_did: &DidValue,
        _algorithm: &str,
        _auth_fn: AuthenticationFn,
        _context: FormatPresentationCtx,
    ) -> Result<String, FormatterError> {
        todo!()
    }

    async fn extract_presentation(
        &self,
        _token: &str,
        _verification: VerificationFn,
        _context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError> {
        todo!()
    }

    async fn format_credential_presentation(
        &self,
        _credential: CredentialPresentation,
        _holder_binding_ctx: Option<HolderBindingCtx>,
        _holder_binding_fn: Option<AuthenticationFn>,
    ) -> Result<String, FormatterError> {
        todo!()
    }

    fn get_leeway(&self) -> u64 {
        todo!()
    }

    fn get_capabilities(&self) -> FormatterCapabilities {
        FormatterCapabilities {
            signing_key_algorithms: vec![
                "EDDSA".to_owned(),
                "ES256".to_owned(),
                "DILITHIUM".to_owned(),
            ],
            allowed_schema_ids: vec![
                "UtopiaEmploymentDocument".to_string(),
                "UtopiaDrivingLicense".to_string(),
                "IdentityCard".to_string(),
            ],
            features: vec![Features::RequiresSchemaId],
            selective_disclosure: vec![],
            issuance_did_methods: vec![],
            issuance_exchange_protocols: vec![],
            proof_exchange_protocols: vec![ExchangeType::ScanToVerify],
            revocation_methods: vec![RevocationType::None],
            verification_key_algorithms: vec![
                "EDDSA".to_string(),
                "ES256".to_string(),
                "DILITHIUM".to_string(),
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
        }
    }

    async fn extract_presentation_unverified(
        &self,
        _token: &str,
        _context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError> {
        todo!()
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
}

#[allow(clippy::new_without_default)]
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
