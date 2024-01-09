use crate::{error::BindingError, utils::into_uuid, OneCoreBinding};

impl OneCoreBinding {
    pub fn delete_credential(&self, credential_id: String) -> Result<(), BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .credential_service
                .delete_credential(&into_uuid(&credential_id)?)
                .await?)
        })
    }
}