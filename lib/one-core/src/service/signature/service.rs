use uuid::Uuid;

use super::SignatureService;
use crate::provider::signer::dto::{CreateSignatureRequestDTO, CreateSignatureResponseDTO};
use crate::service::error::{MissingProviderError, ServiceError};

impl SignatureService {
    pub async fn sign(
        &self,
        request: CreateSignatureRequestDTO,
    ) -> Result<CreateSignatureResponseDTO, ServiceError> {
        let signature_type = request.signer.to_owned();
        let identifier = request.issuer;
        let result = match self.signer_provider.get_from_type(request.signer.as_str()) {
            Some(signer) => signer.sign(request).await?,
            None => {
                return Err(ServiceError::MissingProvider(MissingProviderError::Signer(
                    request.signer,
                )));
            }
        };
        tracing::info!(
            "Created signature {} using identifier {identifier}: signature type `{}`",
            result.id,
            signature_type
        );
        Ok(result)
    }

    pub async fn revoke(&self, id: Uuid) -> Result<(), ServiceError> {
        self.signer_provider
            .get_for_signature_id(id)
            .await?
            .revoke(id)
            .await?;
        tracing::info!("Revoked signature {}", id);
        Ok(())
    }
}
