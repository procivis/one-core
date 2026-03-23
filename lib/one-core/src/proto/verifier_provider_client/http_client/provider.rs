use super::HTTPVerifierProviderClient;
use super::dto::VerifierProviderMetadataResponseRestDTO;
use crate::error::ContextWithErrorCode;
use crate::proto::verifier_provider_client::VerifierProviderClient;
use crate::proto::verifier_provider_client::error::VerifierProviderClientError;
use crate::service::verifier_provider::dto::VerifierProviderMetadataResponseDTO;

#[async_trait::async_trait]
impl VerifierProviderClient for HTTPVerifierProviderClient {
    async fn get_verifier_provider_metadata(
        &self,
        verifier_provider_metadata_url: &str,
    ) -> Result<VerifierProviderMetadataResponseDTO, VerifierProviderClientError> {
        let response = async {
            self.http_client
                .get(verifier_provider_metadata_url)
                .send()
                .await?
                .error_for_status()?
                .json::<VerifierProviderMetadataResponseRestDTO>()
        }
        .await
        .error_while("fetching verifier provider metadata")?;

        Ok(response.into())
    }
}
