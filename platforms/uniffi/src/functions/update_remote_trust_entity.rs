use crate::error::BindingError;
use crate::utils::into_id;
use crate::{OneCoreBinding, UpdateRemoteTrustEntityFromDidRequestBindingDTO};

impl OneCoreBinding {
    pub fn update_remote_trust_entity(
        &self,
        request: UpdateRemoteTrustEntityFromDidRequestBindingDTO,
    ) -> Result<(), BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .trust_entity_service
                .update_remote_trust_entity_for_did(into_id(&request.did_id)?, request.try_into()?)
                .await?)
        })
    }
}
