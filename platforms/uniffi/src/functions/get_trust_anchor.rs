use crate::error::BindingError;
use crate::utils::into_id;
use crate::{GetTrustAnchorResponseBindingDTO, OneCoreBinding};

impl OneCoreBinding {
    pub fn get_trust_anchor(
        &self,
        trust_anchor_id: String,
    ) -> Result<GetTrustAnchorResponseBindingDTO, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .trust_anchor_service
                .get_trust_anchor(into_id(&trust_anchor_id)?)
                .await?
                .into())
        })
    }
}
