use crate::{dto::DidRequestBindingDTO, utils::run_sync, OneCoreBinding};
use one_core::service::error::ServiceError;

impl OneCoreBinding {
    pub fn create_did(&self, request: DidRequestBindingDTO) -> Result<String, ServiceError> {
        run_sync(async {
            self.inner
                .did_service
                .create_did(request.try_into()?)
                .await
                .map(|id| id.to_string())
        })
    }
}
