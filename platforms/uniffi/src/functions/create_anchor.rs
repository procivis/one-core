use crate::{error::BindingError, CreateTrustAnchorRequestBindingDTO, OneCoreBinding};

impl OneCoreBinding {
    pub fn create_trust_anchor(
        &self,
        anchor: CreateTrustAnchorRequestBindingDTO,
    ) -> Result<(), BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            core.trust_anchor_service
                .create_trust_anchor(anchor.try_into()?)
                .await
                .map_err(Into::into)
        })
    }
}
