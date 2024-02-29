use serde::Deserialize;

use std::sync::Arc;
use std::vec;

use crate::crypto::CryptoProvider;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{CredentialStatus, DetailCredential};
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::service::credential::dto::CredentialDetailResponseDTO;
use async_trait::async_trait;
use shared_types::DidValue;

use super::json_ld::model::LdCredential;
use super::model::{CredentialPresentation, Presentation};
use super::{AuthenticationFn, CredentialFormatter, FormatterCapabilities, VerificationFn};

mod base_proof;
mod derived_proof;
mod mapper;
pub mod model;
mod verify_proof;

#[cfg(test)]
mod test;

#[allow(dead_code)]
pub struct JsonLdBbsplus {
    pub base_url: Option<String>,
    pub crypto: Arc<dyn CryptoProvider>,
    pub did_method_provider: Arc<dyn DidMethodProvider>,
    pub key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    params: Params,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {}

#[async_trait]
impl CredentialFormatter for JsonLdBbsplus {
    async fn format_credentials(
        &self,
        credential: &CredentialDetailResponseDTO,
        credential_status: Option<CredentialStatus>,
        holder_did: &DidValue,
        algorithm: &str,
        additional_context: Vec<String>,
        additional_types: Vec<String>,
        auth_fn: AuthenticationFn,
    ) -> Result<String, FormatterError> {
        self.format(
            credential,
            credential_status,
            holder_did,
            algorithm,
            additional_context,
            additional_types,
            auth_fn,
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

    async fn peek(&self, credential: &str) -> Result<DetailCredential, FormatterError> {
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
        _nonce: Option<String>,
    ) -> Result<String, FormatterError> {
        unimplemented!()
    }

    async fn extract_presentation(
        &self,
        _json_ld: &str,
        _verification_fn: VerificationFn,
    ) -> Result<Presentation, FormatterError> {
        unimplemented!()
    }

    fn get_leeway(&self) -> u64 {
        0
    }

    fn get_capabilities(&self) -> FormatterCapabilities {
        FormatterCapabilities {
            signing_key_algorithms: vec!["BBS_PLUS".to_owned()],
            features: vec!["SELECTIVE_DISCLOSURE".to_owned()],
        }
    }
}

impl JsonLdBbsplus {
    #[allow(clippy::new_without_default)]
    pub fn new(
        params: Params,
        crypto: Arc<dyn CryptoProvider>,
        base_url: Option<String>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    ) -> Self {
        Self {
            params,
            crypto,
            base_url,
            did_method_provider,
            key_algorithm_provider,
        }
    }
}
