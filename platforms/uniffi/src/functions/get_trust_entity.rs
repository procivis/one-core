use crate::dto::GetTrustEntityResponseBindingDTO;
use crate::error::BindingError;
use crate::utils::into_id;
use crate::OneCoreBinding;

impl OneCoreBinding {
    pub fn get_trust_entity(
        &self,
        trust_entity_id: String,
    ) -> Result<GetTrustEntityResponseBindingDTO, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .trust_entity_service
                .get_trust_entity(into_id(&trust_entity_id)?)
                .await?
                .into())
        })
    }
}
