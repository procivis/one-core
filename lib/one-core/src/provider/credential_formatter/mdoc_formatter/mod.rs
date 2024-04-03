// https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html

use async_trait::async_trait;
use serde::Deserialize;
use serde_with::serde_as;
use shared_types::DidValue;
use time::Duration;

use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::DetailCredential;

use super::model::{CredentialPresentation, Presentation};
use super::{
    AuthenticationFn, CredentialData, CredentialFormatter, FormatterCapabilities, VerificationFn,
};

pub struct MdocFormatter {}

#[derive(Deserialize)]
#[serde_as]
#[serde(rename_all = "camelCase")]
pub struct Params {
    #[serde_as(as = "DurationSeconds<u64>")]
    pub mso_expires_in: Duration,
    #[serde_as(as = "DurationSeconds<u64>")]
    pub mso_expected_update_in: Duration,
}

#[async_trait]
impl CredentialFormatter for MdocFormatter {
    async fn format_credentials(
        &self,
        _credential: CredentialData,
        _holder_did: &DidValue,
        _algorithm: &str,
        _additional_context: Vec<String>,
        _additional_types: Vec<String>,
        _auth_fn: AuthenticationFn,
        _json_ld_context_url: Option<String>,
        _custom_subject_name: Option<String>,
    ) -> Result<String, FormatterError> {
        todo!()
    }

    async fn extract_credentials(
        &self,
        _credentials: &str,
        _verification: VerificationFn,
    ) -> Result<DetailCredential, FormatterError> {
        todo!()
    }

    async fn extract_credentials_unverified(
        &self,
        _token: &str,
    ) -> Result<DetailCredential, FormatterError> {
        todo!()
    }

    async fn format_presentation(
        &self,
        _tokens: &[String],
        _holder_did: &DidValue,
        _algorithm: &str,
        _auth_fn: AuthenticationFn,
        _nonce: Option<String>,
    ) -> Result<String, FormatterError> {
        todo!()
    }

    async fn extract_presentation(
        &self,
        _token: &str,
        _verification: VerificationFn,
    ) -> Result<Presentation, FormatterError> {
        todo!()
    }

    async fn format_credential_presentation(
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
            features: vec!["SELECTIVE_DISCLOSURE".to_string()],
            issuance_exchange_protocols: vec!["OPENID4VC".to_string()],
            proof_exchange_protocols: vec![],
            revocation_methods: vec!["NONE".to_string()],
            signing_key_algorithms: vec!["EDDSA".to_string(), "ES256".to_string()],
        }
    }

    async fn extract_presentation_unverified(
        &self,
        _token: &str,
    ) -> Result<Presentation, FormatterError> {
        todo!()
    }
}

impl MdocFormatter {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {}
    }
}
