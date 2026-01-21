use std::sync::Arc;

use async_trait::async_trait;

use crate::model::identifier::Identifier;
use crate::provider::revocation::RevocationMethod;
use crate::provider::signer::dto::RevocationInfo;
use crate::provider::signer::error::SignerError;

pub mod dto;
pub mod error;
pub mod model;
pub mod provider;
pub mod registration_certificate;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub trait Signer: Send + Sync {
    fn get_capabilities(&self) -> model::SignerCapabilities;

    async fn sign(
        &self,
        issuer: Identifier,
        request: dto::CreateSignatureRequestDTO,
        revocation_info: Option<RevocationInfo>,
    ) -> Result<dto::CreateSignatureResponseDTO, SignerError>;

    fn revocation_method(&self) -> Option<Arc<dyn RevocationMethod>>;
}
