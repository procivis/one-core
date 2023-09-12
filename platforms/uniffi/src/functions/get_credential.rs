use crate::{utils::run_sync, CredentialDetailBindingDTO, OneCoreBinding};
use one_core::service::error::ServiceError;
use uuid::Uuid;

impl OneCoreBinding {
    pub fn get_credential(
        &self,
        credential_id: String,
    ) -> Result<CredentialDetailBindingDTO, ServiceError> {
        let credential_id = Uuid::parse_str(&credential_id)
            .map_err(|e| ServiceError::MappingError(e.to_string()))?;

        run_sync(async {
            Ok(self
                .inner
                .credential_service
                .get_credential(&credential_id)
                .await?
                .into())
        })
    }
}
