use crate::{dto::ConfigBindingDTO, error::BindingError, OneCoreBinding};

impl OneCoreBinding {
    pub fn get_config(&self) -> Result<ConfigBindingDTO, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            let config = core.config_service.get_config()?;
            Ok(config.into())
        })
    }
}
