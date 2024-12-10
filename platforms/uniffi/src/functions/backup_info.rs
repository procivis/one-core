use crate::error::BindingError;
use crate::{OneCoreBinding, UnexportableEntitiesBindingDTO};

#[uniffi::export]
impl OneCoreBinding {
    #[uniffi::method]
    pub fn backup_info(&self) -> Result<UnexportableEntitiesBindingDTO, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core.backup_service.backup_info().await?.into())
        })
    }
}
