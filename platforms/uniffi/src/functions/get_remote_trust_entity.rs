use crate::error::BindingError;
use crate::utils::into_id;
use crate::{GetTrustEntityResponseBindingDTO, OneCoreBinding};

#[uniffi::export]
impl OneCoreBinding {
    #[uniffi::method]
    pub fn get_remote_trust_entity(
        &self,
        did_id: String,
    ) -> Result<GetTrustEntityResponseBindingDTO, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .trust_entity_service
                .get_remote_trust_entity_for_did(into_id(&did_id)?)
                .await?
                .into())
        })
    }
}
