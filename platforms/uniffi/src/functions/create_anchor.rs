use crate::error::BindingError;
use crate::{CreateTrustAnchorRequestBindingDTO, OneCoreBinding};

impl OneCoreBinding {
    pub fn create_trust_anchor(
        &self,
        anchor: CreateTrustAnchorRequestBindingDTO,
    ) -> Result<String, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            let id = core
                .trust_anchor_service
                .create_trust_anchor(anchor.try_into()?)
                .await?;
            Ok(id.to_string())
        })
    }
}
