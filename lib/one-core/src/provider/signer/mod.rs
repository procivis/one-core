use async_trait::async_trait;
use uuid::Uuid;

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
        request: dto::CreateSignatureRequestDTO,
    ) -> Result<dto::CreateSignatureResponseDTO, SignerError>;

    async fn revoke(&self, id: Uuid) -> Result<(), SignerError>;
}
