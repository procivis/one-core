use std::sync::Arc;

use dto::VerifierProviderMetadataResponseDTO;

use crate::error::ContextWithErrorCode;
use crate::provider::verifier::error::VerifierProviderError;
use crate::provider::verifier::provider::VerifierProviderDirectory;

pub mod dto;

pub struct VerifierProviderService {
    verifier_provider_directory: Arc<dyn VerifierProviderDirectory>,
}

impl VerifierProviderService {
    pub(crate) fn new(verifier_provider_directory: Arc<dyn VerifierProviderDirectory>) -> Self {
        Self {
            verifier_provider_directory,
        }
    }

    pub async fn get_verifier_by_id(
        &self,
        id: &str,
    ) -> Result<VerifierProviderMetadataResponseDTO, VerifierProviderError> {
        let verifier_provider = self
            .verifier_provider_directory
            .get_provider(id)
            .error_while("getting verifier provider")?;

        verifier_provider.get_metadata().await
    }
}
