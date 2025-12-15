use uuid::Uuid;

use super::SignatureService;
use crate::provider::signer::dto::{CreateSignatureRequestDTO, CreateSignatureResponseDTO};
use crate::service::error::{MissingProviderError, ServiceError};

impl SignatureService {
    pub async fn sign(
        &self,
        request: CreateSignatureRequestDTO,
    ) -> Result<CreateSignatureResponseDTO, ServiceError> {
        match self.signer_provider.get_from_type(request.signer.as_str()) {
            Some(signer) => signer.sign(request).await,
            None => Err(ServiceError::MissingProvider(MissingProviderError::Signer(
                request.signer,
            ))),
        }
    }

    pub async fn revoke(&self, id: Uuid) -> Result<(), ServiceError> {
        self.signer_provider
            .get_for_signature_id(id)
            .await?
            .revoke(id)
            .await
    }
}
