use crate::{dto::KeyRequestBindingDTO, error::BindingError, utils::run_sync, OneCoreBinding};

impl OneCoreBinding {
    pub fn generate_key(&self, request: KeyRequestBindingDTO) -> Result<String, BindingError> {
        run_sync(async {
            let core = self.use_core().await?;
            Ok(core
                .key_service
                .generate_key(request.try_into()?)
                .await?
                .to_string())
        })
    }
}
