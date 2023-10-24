pub mod error;
pub mod model;

// Implementations
mod jwt;

pub mod jwt_formatter;
pub mod sdjwt_formatter;
pub mod status_list_2021_jwt_formatter;

pub(crate) mod provider;

use crate::service::credential::dto::CredentialDetailResponseDTO;

use self::{
    error::FormatterError,
    jwt::{AuthenticationFn, VerificationFn},
    model::{CredentialPresentation, CredentialStatus, DetailCredential, PresentationCredential},
};

#[allow(clippy::too_many_arguments)]
#[cfg_attr(test, mockall::automock)]
pub trait CredentialFormatter {
    fn format_credentials(
        &self,
        credential: &CredentialDetailResponseDTO,
        credential_status: Option<CredentialStatus>,
        holder_did: &str,
        algorithm: &str,
        additional_context: Vec<String>,
        additional_types: Vec<String>,
        auth_fn: AuthenticationFn,
    ) -> Result<String, FormatterError>;

    fn extract_credentials(
        &self,
        credentials: &str,
        verify_fn: VerificationFn,
    ) -> Result<DetailCredential, FormatterError>;

    fn format_presentation(
        &self,
        tokens: &[PresentationCredential],
        holder_did: &str,
        algorithm: &str,
        auth_fn: AuthenticationFn,
    ) -> Result<String, FormatterError>;

    fn extract_presentation(
        &self,
        token: &str,
        verify_fn: VerificationFn,
    ) -> Result<CredentialPresentation, FormatterError>;

    fn get_leeway(&self) -> u64;
}
