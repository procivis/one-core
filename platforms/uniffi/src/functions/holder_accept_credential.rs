use crate::{
    error::BindingError,
    utils::{into_uuid, run_sync},
    OneCoreBinding,
};

impl OneCoreBinding {
    pub fn holder_accept_credential(&self, interaction_id: String) -> Result<(), BindingError> {
        run_sync(async {
            Ok(self
                .inner
                .ssi_holder_service
                .accept_credential(&into_uuid(&interaction_id)?)
                .await?)
        })
    }
}
