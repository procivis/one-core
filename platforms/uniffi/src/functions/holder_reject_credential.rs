use crate::{error::BindingError, utils::into_uuid, OneCoreBinding};

impl OneCoreBinding {
    pub fn holder_reject_credential(&self, interaction_id: String) -> Result<(), BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .ssi_holder_service
                .reject_credential(&into_uuid(&interaction_id)?)
                .await?)
        })
    }
}
