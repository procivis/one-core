use crate::dto::KeyRequestBindingDTO;
use crate::error::BindingError;
use crate::OneCoreBinding;

impl OneCoreBinding {
    pub fn generate_key(&self, request: KeyRequestBindingDTO) -> Result<String, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .key_service
                .generate_key(request.try_into()?)
                .await?
                .to_string())
        })
    }
}
