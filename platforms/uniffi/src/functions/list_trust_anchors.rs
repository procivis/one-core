use crate::error::BindingError;
use crate::{ListTrustAnchorsFiltersBindings, OneCoreBinding, TrustAnchorsListBindingDTO};

#[uniffi::export]
impl OneCoreBinding {
    #[uniffi::method]
    pub fn list_trust_anchors(
        &self,
        filters: ListTrustAnchorsFiltersBindings,
    ) -> Result<TrustAnchorsListBindingDTO, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .trust_anchor_service
                .list_trust_anchors(filters.try_into()?)
                .await?
                .into())
        })
    }
}
