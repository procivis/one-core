use std::sync::Arc;

use async_trait::async_trait;

use crate::provider::revocation::RevocationMethod;
use crate::provider::signer::dto::Issuer;
use crate::provider::signer::error::SignerError;

mod access_certificate;
pub mod dto;
pub mod error;
pub mod model;
pub mod provider;
pub mod registration_certificate;
mod validity;
pub mod x509_certificate;
mod x509_utils;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub trait Signer: Send + Sync {
    fn get_capabilities(&self) -> model::SignerCapabilities;

    async fn sign(
        &self,
        issuer: Issuer,
        request: dto::CreateSignatureRequest,
    ) -> Result<dto::CreateSignatureResponseDTO, SignerError>;

    fn revocation_method(&self) -> Option<Arc<dyn RevocationMethod>>;
}
