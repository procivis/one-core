use std::sync::Arc;
use std::vec;

use one_providers::crypto::CryptoProvider;
use one_providers::key_algorithm::provider::KeyAlgorithmProvider;

use async_trait::async_trait;
use serde::Deserialize;
use serde_with::{serde_as, DurationSeconds};
use shared_types::DidValue;
use time::Duration;

use crate::config::core_config::JsonLdContextConfig;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::json_ld::caching_loader::CachingLoader;
use crate::provider::credential_formatter::model::DetailCredential;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::repository::json_ld_context_repository::JsonLdContextRepository;

use super::json_ld::model::LdCredential;
use super::model::{CredentialPresentation, Presentation};
use super::{
    AuthenticationFn, CredentialData, CredentialFormatter, ExtractPresentationCtx,
    FormatPresentationCtx, FormatterCapabilities, SelectiveDisclosureOption, VerificationFn,
};

mod base_proof;
mod derived_proof;
mod mapper;
pub mod model;
mod remove_undisclosed_keys;
mod verify_proof;

#[cfg(test)]
mod test;

#[allow(dead_code)]
pub struct JsonLdBbsplus {
    pub base_url: Option<String>,
    pub crypto: Arc<dyn CryptoProvider>,
    pub did_method_provider: Arc<dyn DidMethodProvider>,
    pub key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    pub caching_loader: CachingLoader,
    params: Params,
}

#[serde_with::serde_as]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    #[serde_as(as = "DurationSeconds<i64>")]
    leeway: Duration,
}

#[async_trait]
impl CredentialFormatter for JsonLdBbsplus {
    async fn format_credentials(
        &self,
        credential: CredentialData,
        holder_did: &DidValue,
        algorithm: &str,
        additional_context: Vec<String>,
        additional_types: Vec<String>,
        auth_fn: AuthenticationFn,
        json_ld_context_url: Option<String>,
        custom_subject_name: Option<String>,
    ) -> Result<String, FormatterError> {
        self.format(
            credential,
            holder_did,
            algorithm,
            additional_context,
            additional_types,
            auth_fn,
            json_ld_context_url,
            custom_subject_name,
        )
        .await
    }

    async fn extract_credentials(
        &self,
        credential: &str,
        verification_fn: VerificationFn,
    ) -> Result<DetailCredential, FormatterError> {
        self.verify(credential, verification_fn).await
    }

    async fn extract_credentials_unverified(
        &self,
        credential: &str,
    ) -> Result<DetailCredential, FormatterError> {
        let ld_credential: LdCredential = serde_json::from_str(credential).map_err(|e| {
            FormatterError::CouldNotVerify(format!("Could not deserialize base proof: {e}"))
        })?;
        ld_credential.try_into()
    }

    async fn format_credential_presentation(
        &self,
        credential: CredentialPresentation,
    ) -> Result<String, FormatterError> {
        self.derive_proof(credential).await
    }

    async fn format_presentation(
        &self,
        _tokens: &[String],
        _holder_did: &DidValue,
        _algorithm: &str,
        _auth_fn: AuthenticationFn,
        _context: FormatPresentationCtx,
    ) -> Result<String, FormatterError> {
        unimplemented!()
    }

    async fn extract_presentation(
        &self,
        _json_ld: &str,
        _verification_fn: VerificationFn,
        _context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError> {
        unimplemented!()
    }

    fn get_leeway(&self) -> u64 {
        self.params.leeway.whole_seconds() as u64
    }

    fn get_capabilities(&self) -> FormatterCapabilities {
        FormatterCapabilities {
            signing_key_algorithms: vec!["BBS_PLUS".to_owned()],
            features: vec!["SELECTIVE_DISCLOSURE".to_owned()],
            selective_disclosure: vec![SelectiveDisclosureOption::AnyLevel],
            issuance_did_methods: vec![
                "KEY".to_string(),
                "WEB".to_string(),
                "JWK".to_string(),
                "X509".to_string(),
            ],
            issuance_exchange_protocols: vec![
                "OPENID4VC".to_string(),
                "PROCIVIS_TEMPORARY".to_string(),
            ],
            proof_exchange_protocols: vec![
                "OPENID4VC".to_string(),
                "PROCIVIS_TEMPORARY".to_string(),
            ],
            revocation_methods: vec![
                "NONE".to_string(),
                "BITSTRINGSTATUSLIST".to_string(),
                "LVVC".to_string(),
            ],
            verification_key_algorithms: vec![
                "EDDSA".to_string(),
                "ES256".to_string(),
                "DILITHIUM".to_string(),
            ],
        }
    }

    async fn extract_presentation_unverified(
        &self,
        _token: &str,
        _context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError> {
        unimplemented!()
    }
}

impl JsonLdBbsplus {
    #[allow(clippy::new_without_default)]
    pub fn new(
        params: Params,
        crypto: Arc<dyn CryptoProvider>,
        base_url: Option<String>,
        json_ld_context_config: JsonLdContextConfig,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        json_ld_context_repository: Arc<dyn JsonLdContextRepository>,
    ) -> Self {
        Self {
            params,
            crypto,
            base_url,
            did_method_provider,
            key_algorithm_provider,
            caching_loader: CachingLoader {
                cache_size: json_ld_context_config.cache_size,
                cache_refresh_timeout: json_ld_context_config.cache_refresh_timeout,
                client: Default::default(),
                json_ld_context_repository,
            },
        }
    }
}
