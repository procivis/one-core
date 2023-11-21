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
use shared_types::DidValue;

use crate::{
    crypto::signer::error::SignerError, service::credential::dto::CredentialDetailResponseDTO,
};

use self::{
    error::FormatterError,
    model::{CredentialPresentation, CredentialStatus, DetailCredential, Presentation},
};

pub type AuthenticationFn = Box<dyn SignatureProvider + Send + Sync>;
pub type VerificationFn = Box<dyn TokenVerifier + Send + Sync>;

#[async_trait]
pub trait TokenVerifier {
    async fn verify<'a>(
        &self,
        issuer_did_value: Option<DidValue>,
        algorithm: &'a str,
        token: &'a str,
        signature: &'a [u8],
    ) -> Result<(), SignerError>;
}

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait SignatureProvider {
    async fn sign(&self, message: &str) -> Result<Vec<u8>, SignerError>;
}

#[allow(clippy::too_many_arguments)]
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait CredentialFormatter {
    async fn format_credentials(
        &self,
        credential: &CredentialDetailResponseDTO,
        credential_status: Option<CredentialStatus>,
        holder_did: &DidValue,
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

    fn format_credential_presentation(
        &self,
        credential: CredentialPresentation,
    ) -> Result<String, FormatterError>;

    async fn format_presentation(
        &self,
        tokens: &[String],
        holder_did: &DidValue,
        algorithm: &str,
        auth_fn: AuthenticationFn,
        nonce: Option<String>,
    ) -> Result<String, FormatterError>;

    async fn extract_presentation(
        &self,
        token: &str,
        verification: Box<dyn TokenVerifier + Send + Sync>,
    ) -> Result<Presentation, FormatterError>;

    fn get_leeway(&self) -> u64;
}

#[cfg(test)]
#[derive(Clone)]
pub(crate) struct MockAuth<F: Fn(&str) -> Vec<u8> + Send + Sync>(pub F);
#[cfg(test)]
#[async_trait::async_trait]
impl<F: Fn(&str) -> Vec<u8> + Send + Sync> SignatureProvider for MockAuth<F> {
    async fn sign(&self, message: &str) -> Result<Vec<u8>, SignerError> {
        Ok(self.0(message))
    }
}
