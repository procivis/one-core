use std::path::Path;

use crate::error::BindingError;
use crate::{MetadataBindingDTO, OneCoreBinding};

impl OneCoreBinding {
    pub fn unpack_backup(
        &self,
        password: String,
        input_path: String,
    ) -> Result<MetadataBindingDTO, BindingError> {
        if Path::new(&self.backup_db_path).exists() {
            return Err(BindingError::AlreadyExists(
                "backup file already exists".into(),
            ));
        }

        let metadata = self.block_on(async {
            let core = self.use_core().await?;
            Ok::<_, BindingError>(
                core.backup_service
                    .unpack_backup(password, input_path, self.backup_db_path.clone())
                    .await?
                    .into(),
            )
        })?;

        self.initialize(self.backup_db_path.clone())?;
        Ok(metadata)
    }
}
