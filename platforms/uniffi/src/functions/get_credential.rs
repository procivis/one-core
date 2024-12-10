use crate::error::BindingError;
use crate::utils::into_id;
use crate::{CredentialDetailBindingDTO, OneCoreBinding};

#[uniffi::export]
impl OneCoreBinding {
    #[uniffi::method]
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
