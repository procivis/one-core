use crate::{dto::DidRequestBindingDTO, error::BindingError, utils::run_sync, OneCoreBinding};

impl OneCoreBinding {
    pub fn create_did(&self, request: DidRequestBindingDTO) -> Result<String, BindingError> {
        run_sync(async {
            Ok(self
                .inner
                .did_service
                .create_did(request.try_into()?)
                .await?
                .to_string())
        })
    }
}
