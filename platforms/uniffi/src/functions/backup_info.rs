use crate::{error::BindingError, OneCoreBinding, UnexportableEntitiesBindingDTO};

impl OneCoreBinding {
    pub fn backup_info(&self) -> Result<UnexportableEntitiesBindingDTO, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core.backup_service.backup_info().await?.into())
        })
    }
}
