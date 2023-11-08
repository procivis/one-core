use crate::{
    error::BindingError,
    utils::{into_uuid, run_sync},
    CredentialDetailBindingDTO, OneCoreBinding,
};

impl OneCoreBinding {
    pub fn get_credential(
        &self,
        credential_id: String,
    ) -> Result<CredentialDetailBindingDTO, BindingError> {
        run_sync(async {
            Ok(self
                .inner
                .credential_service
                .get_credential(&into_uuid(&credential_id)?)
                .await?
                .into())
        })
    }
}
