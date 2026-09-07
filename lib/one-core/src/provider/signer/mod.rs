use std::fmt::{Display, Formatter};
use std::sync::Arc;

use async_trait::async_trait;
use proc_macros::provider_mock;
use shared_types::SignerId;

use crate::provider::Provider;
use crate::provider::revocation::RevocationMethod;
use crate::provider::signer::dto::Issuer;
use crate::provider::signer::error::SignerError;

mod access_certificate;
mod decorators;
pub mod dto;
pub mod error;
pub mod model;
pub mod provider;
pub mod registration_certificate;
pub mod swiyu_proof_of_possession;
mod validity;
pub mod x509_certificate;
mod x509_utils;

#[provider_mock]
#[async_trait]
pub trait Signer: Provider + Send + Sync {
    fn get_capabilities(&self) -> model::SignerCapabilities;

    async fn sign(
        &self,
        issuer: Issuer,
        request: dto::CreateSignatureRequest,
    ) -> Result<dto::CreateSignatureResponseDTO, SignerError>;

    fn revocation_method(&self) -> Result<Option<Arc<dyn RevocationMethod>>, SignerError>;

    fn config_name(&self) -> &SignerId;
}

impl Display for dyn Signer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signer `{}`", self.config_name())
    }
}
