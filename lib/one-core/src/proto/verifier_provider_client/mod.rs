pub mod error;
pub mod http_client;

use error::VerifierProviderClientError;

use crate::service::verifier_provider::dto::VerifierProviderMetadataResponseDTO;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
#[expect(unused)]
pub trait VerifierProviderClient: Send + Sync {
    async fn get_verifier_provider_metadata(
        &self,
        verifier_provider_metadata_url: &str,
    ) -> Result<VerifierProviderMetadataResponseDTO, VerifierProviderClientError>;
}
