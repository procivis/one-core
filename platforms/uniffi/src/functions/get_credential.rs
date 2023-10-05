use crate::{
    utils::{into_uuid, run_sync},
    CredentialDetailBindingDTO, OneCoreBinding,
};
use one_core::service::error::ServiceError;

impl OneCoreBinding {
    pub fn get_credential(
        &self,
        credential_id: String,
    ) -> Result<CredentialDetailBindingDTO, ServiceError> {
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
