use std::path::Path;

use crate::{error::BindingError, OneCoreBinding};

impl OneCoreBinding {
    pub fn rollback_import(&self) -> Result<(), BindingError> {
        if !Path::new(&self.backup_db_path).exists() {
            return Err(BindingError::NotFound("no active backup file found".into()));
        }

        self.initialize(self.main_db_path.clone())?;
        std::fs::remove_file(&self.backup_db_path)?;
        Ok(())
    }
}
