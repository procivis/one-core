use std::path::Path;

use crate::{error::BindingError, OneCoreBinding};

impl OneCoreBinding {
    pub fn finalize_import(&self) -> Result<(), BindingError> {
        if !Path::new(&self.backup_db_path).exists() {
            return Err(BindingError::NotFound("no active backup file found".into()));
        }

        self.uninitialize(false)?;
        std::fs::copy(&self.backup_db_path, &self.main_db_path)?;
        self.initialize(self.main_db_path.clone())?;
        std::fs::remove_file(&self.backup_db_path)?;

        self.block_on(async {
            let core = self.use_core().await?;
            core.backup_service.finalize_import().await;
            Ok(())
        })
    }
}
