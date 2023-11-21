// https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html

use crate::config::data_structure::FormatJwtParams;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{CredentialStatus, DetailCredential};
use crate::service::credential::dto::CredentialDetailResponseDTO;
use async_trait::async_trait;
use shared_types::DidValue;

use super::model::{CredentialPresentation, Presentation};
use super::{AuthenticationFn, CredentialFormatter, VerificationFn};

pub struct MdocFormatter {
    pub params: FormatJwtParams,
}

#[async_trait]
impl CredentialFormatter for MdocFormatter {
    async fn format_credentials(
        &self,
        _credential: &CredentialDetailResponseDTO,
        _credential_status: Option<CredentialStatus>,
        _holder_did: &DidValue,
        _algorithm: &str,
        _additional_context: Vec<String>,
        _additional_types: Vec<String>,
        _auth_fn: AuthenticationFn,
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

    fn format_credential_presentation(
        &self,
        _credential: CredentialPresentation,
    ) -> Result<String, FormatterError> {
        todo!()
    }

    fn get_leeway(&self) -> u64 {
        todo!()
    }
}
