use crate::dto::DidRequestBindingDTO;
use crate::error::BindingError;
use crate::OneCoreBinding;

impl OneCoreBinding {
    pub fn create_did(&self, request: DidRequestBindingDTO) -> Result<String, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .did_service
                .create_did(request.try_into()?)
                .await?
                .to_string())
        })
    }
}
