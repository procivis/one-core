use std::path::Path;

use one_core::service::error::ServiceError;

use crate::error::BindingError;
use crate::OneCoreBinding;

#[uniffi::export]
impl OneCoreBinding {
    #[uniffi::method]
    pub fn finalize_import(&self) -> Result<(), BindingError> {
        if !Path::new(&self.backup_db_path).exists() {
            return Err(ServiceError::ValidationError("no active backup file found".into()).into());
        }

        self.uninitialize(false)?;
        std::fs::copy(&self.backup_db_path, &self.main_db_path)
            .map_err(|e| ServiceError::Other(e.to_string()))?;
        self.initialize(self.main_db_path.clone())?;
        std::fs::remove_file(&self.backup_db_path)
            .map_err(|e| ServiceError::Other(e.to_string()))?;

        self.block_on(async {
            let core = self.use_core().await?;
            core.backup_service.finalize_import().await;
            Ok(())
        })
    }
}
