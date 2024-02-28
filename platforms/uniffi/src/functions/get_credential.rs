use crate::{error::BindingError, utils::into_id, CredentialDetailBindingDTO, OneCoreBinding};

impl OneCoreBinding {
    pub fn get_credential(
        &self,
        credential_id: String,
    ) -> Result<CredentialDetailBindingDTO, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .credential_service
                .get_credential(&into_id(&credential_id)?)
                .await?
                .into())
        })
    }
}
