// https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html

use crate::config::data_structure::FormatJwtParams;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::jwt::{AuthenticationFn, TokenVerifier};
use crate::provider::credential_formatter::model::{
    CredentialPresentation, CredentialStatus, DetailCredential, PresentationCredential,
};
use crate::service::credential::dto::CredentialDetailResponseDTO;
use async_trait::async_trait;

use super::CredentialFormatter;

pub struct JsonLdFormatter {
    pub params: FormatJwtParams,
}

#[async_trait]
impl CredentialFormatter for JsonLdFormatter {
    fn format_credentials(
        &self,
        _credential: &CredentialDetailResponseDTO,
        _credential_status: Option<CredentialStatus>,
        _holder_did: &str,
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
        _verification: Box<dyn TokenVerifier + Send + Sync>,
    ) -> Result<DetailCredential, FormatterError> {
        todo!()
    }

    fn format_presentation(
        &self,
        _tokens: &[PresentationCredential],
        _holder_did: &str,
        _algorithm: &str,
        _auth_fn: AuthenticationFn,
    ) -> Result<String, FormatterError> {
        todo!()
    }

    async fn extract_presentation(
        &self,
        _token: &str,
        _verification: Box<dyn TokenVerifier + Send + Sync>,
    ) -> Result<CredentialPresentation, FormatterError> {
        todo!()
    }

    fn get_leeway(&self) -> u64 {
        todo!()
    }
}
