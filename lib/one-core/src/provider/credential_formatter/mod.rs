pub mod error;
pub mod model;

// Implementations
pub mod jwt;

pub mod jwt_formatter;
pub mod sdjwt_formatter;

pub mod json_ld_formatter;
pub mod mdoc_formatter;
pub mod status_list_2021_jwt_formatter;

pub(crate) mod provider;

use async_trait::async_trait;

use crate::service::credential::dto::CredentialDetailResponseDTO;

use self::{
    error::FormatterError,
    jwt::{AuthenticationFn, TokenVerifier},
    model::{CredentialPresentation, CredentialStatus, DetailCredential, PresentationCredential},
};

#[allow(clippy::too_many_arguments)]
#[cfg_attr(test, mockall::automock)]
#[async_trait]
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

    async fn extract_credentials(
        &self,
        credentials: &str,
        verification: Box<dyn TokenVerifier + Send + Sync>,
    ) -> Result<DetailCredential, FormatterError>;

    fn format_presentation(
        &self,
        tokens: &[PresentationCredential],
        holder_did: &str,
        algorithm: &str,
        auth_fn: AuthenticationFn,
    ) -> Result<String, FormatterError>;

    async fn extract_presentation(
        &self,
        token: &str,
        verification: Box<dyn TokenVerifier + Send + Sync>,
    ) -> Result<CredentialPresentation, FormatterError>;

    fn get_leeway(&self) -> u64;
}
