use crate::binding::OneCoreBinding;
use crate::dto::GetTrustEntityResponseBindingDTO;
use crate::error::BindingError;
use crate::utils::into_id;

impl OneCoreBinding {
    pub fn get_trust_entity_by_did(
        &self,
        did_id: String,
    ) -> Result<GetTrustEntityResponseBindingDTO, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            let trust_entity = core
                .trust_entity_service
                .lookup_did(into_id(&did_id)?)
                .await?;

            Ok(trust_entity.into())
        })
    }
}
