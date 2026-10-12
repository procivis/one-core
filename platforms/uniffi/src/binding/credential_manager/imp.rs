use one_core::proto::native_credential_manager::{
    CredentialManagerError, DigitalCredentialRegistration, NativeCredentialManager,
};
use one_dto_mapper::convert_inner;

use super::CredentialManagerWrapper;

#[async_trait::async_trait]
impl NativeCredentialManager for CredentialManagerWrapper {
    async fn synchronize(
        &self,
        credentials: Vec<DigitalCredentialRegistration>,
    ) -> Result<(), CredentialManagerError> {
        self.0
            .synchronize(convert_inner(credentials))
            .await
            .map_err(CredentialManagerError::from)
    }
}
