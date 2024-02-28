use crate::{error::BindingError, BackupCreateBindingDTO, OneCoreBinding};

impl OneCoreBinding {
    pub fn create_backup(
        &self,
        password: String,
        output_path: String,
    ) -> Result<BackupCreateBindingDTO, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .backup_service
                .create_backup(password, output_path)
                .await?
                .into())
        })
    }
}
