use one_core::proto::native_credential_manager::{
    CredentialManagerError, DigitalCredentialRegistration, NativeCredentialManager,
    NativeDcApiResponseHandler,
};
use one_dto_mapper::convert_inner;

use super::{CredentialManagerWrapper, DcApiResponseHandlerWrapper};

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

impl NativeDcApiResponseHandler for DcApiResponseHandlerWrapper {
    fn on_submit(&self, response: String) -> Result<(), CredentialManagerError> {
        self.0
            .on_submit(response)
            .map_err(CredentialManagerError::from)
    }

    fn on_reject(&self) -> Result<(), CredentialManagerError> {
        self.0.on_reject().map_err(CredentialManagerError::from)
    }
}
