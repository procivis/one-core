use crate::error::BindingError;
use crate::{CreateTrustAnchorRequestBindingDTO, OneCoreBinding};

#[uniffi::export]
impl OneCoreBinding {
    #[uniffi::method]
    pub fn create_trust_anchor(
        &self,
        anchor: CreateTrustAnchorRequestBindingDTO,
    ) -> Result<String, BindingError> {
        let request = anchor.into();

        self.block_on(async {
            let core = self.use_core().await?;
            let id = core
                .trust_anchor_service
                .create_trust_anchor(request)
                .await?;
            Ok(id.to_string())
        })
    }
}
