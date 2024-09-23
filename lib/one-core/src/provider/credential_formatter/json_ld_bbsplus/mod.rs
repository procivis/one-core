//! Implementation of JSON-LD credential format with BBS+ signatures, allowing for selective disclosure.

use std::sync::Arc;
use std::vec;

use async_trait::async_trait;
use one_crypto::CryptoProvider;
use serde::Deserialize;
use serde_with::{serde_as, DurationSeconds};
use shared_types::DidValue;
use time::Duration;

use super::json_ld::context::caching_loader::ContextCache;
use super::json_ld::jsonld_forbidden_claim_names;
use super::json_ld::model::{ContextType, LdCredential};
use super::CredentialFormatter;
use crate::model::did::Did;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::json_ld::context::caching_loader::JsonLdCachingLoader;
use crate::provider::credential_formatter::model::{
    AuthenticationFn, CredentialData, CredentialPresentation, DetailCredential,
    ExtractPresentationCtx, FormatPresentationCtx, FormatterCapabilities, Presentation,
    VerificationFn,
};
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::http_client::HttpClient;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::revocation::bitstring_status_list::model::StatusPurpose;

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
    pub caching_loader: ContextCache,
    params: Params,
}

#[serde_with::serde_as]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    #[serde_as(as = "DurationSeconds<i64>")]
    pub leeway: Duration,
    pub embed_layout_properties: Option<bool>,
}

#[async_trait]
impl CredentialFormatter for JsonLdBbsplus {
    async fn format_credentials(
        &self,
        credential: CredentialData,
        holder_did: &Option<DidValue>,
        algorithm: &str,
        additional_context: Vec<ContextType>,
        additional_types: Vec<String>,
        auth_fn: AuthenticationFn,
        json_ld_context_url: Option<String>,
        custom_subject_name: Option<String>,
    ) -> Result<String, FormatterError> {
        let json_ld_context_url = json_ld_context_url
            .map(|ctx| ctx.parse())
            .transpose()
            .map_err(|_err| {
                FormatterError::CouldNotFormat(
                    "Provided JsonLD context needs to be a valid URL".to_string(),
                )
            })?;

        self.format(
            credential,
            holder_did.as_ref(),
            algorithm,
            additional_context,
            additional_types,
            auth_fn,
            json_ld_context_url,
            custom_subject_name,
            self.params.embed_layout_properties.unwrap_or_default(),
        )
        .await
    }

    async fn format_bitstring_status_list(
        &self,
        _revocation_list_url: String,
        _issuer_did: &Did,
        _encoded_list: String,
        _algorithm: String,
        _auth_fn: AuthenticationFn,
        _status_purpose: StatusPurpose,
    ) -> Result<String, FormatterError> {
        Err(FormatterError::Failed(
            "Cannot format BitstringStatusList with BBS+ formatter".to_string(),
        ))
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
            features: vec![
                "SUPPORTS_CREDENTIAL_DESIGN".to_string(),
                "SELECTIVE_DISCLOSURE".to_owned(),
            ],
            selective_disclosure: vec!["ANY_LEVEL".to_owned()],
            issuance_did_methods: vec![
                "KEY".to_string(),
                "WEB".to_string(),
                "JWK".to_string(),
                "X509".to_string(),
            ],
            allowed_schema_ids: vec![],
            datatypes: vec![
                "STRING".to_string(),
                "BOOLEAN".to_string(),
                "EMAIL".to_string(),
                "DATE".to_string(),
                "STRING".to_string(),
                "COUNT".to_string(),
                "BIRTH_DATE".to_string(),
                "NUMBER".to_string(),
                "PICTURE".to_string(),
                "OBJECT".to_string(),
                "ARRAY".to_string(),
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
            verification_key_storages: vec![
                "INTERNAL".to_string(),
                "AZURE_VAULT".to_string(),
                "SECURE_ELEMENT".to_string(),
            ],
            forbidden_claim_names: [jsonld_forbidden_claim_names(), vec!["0".to_string()]].concat(),
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
    pub fn new(
        params: Params,
        crypto: Arc<dyn CryptoProvider>,
        base_url: Option<String>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        caching_loader: JsonLdCachingLoader,
        client: Arc<dyn HttpClient>,
    ) -> Self {
        Self {
            params,
            crypto,
            base_url,
            did_method_provider,
            key_algorithm_provider,
            caching_loader: ContextCache::new(caching_loader, client),
        }
    }
}
