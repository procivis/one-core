use crate::{dto::KeyRequestBindingDTO, utils::run_sync, OneCoreBinding};
use one_core::service::error::ServiceError;

impl OneCoreBinding {
    pub fn generate_key(&self, request: KeyRequestBindingDTO) -> Result<String, ServiceError> {
        run_sync(async {
            Ok(self
                .inner
                .key_service
                .generate_key(request.try_into()?)
                .await?
                .to_string())
        })
    }
}
