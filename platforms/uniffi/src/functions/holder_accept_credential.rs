use crate::{
    utils::{into_uuid, run_sync},
    OneCoreBinding,
};
use one_core::service::error::ServiceError;

impl OneCoreBinding {
    pub fn holder_accept_credential(&self, interaction_id: String) -> Result<(), ServiceError> {
        run_sync(async {
            self.inner
                .ssi_holder_service
                .accept_credential(&into_uuid(&interaction_id)?)
                .await
        })
    }
}
