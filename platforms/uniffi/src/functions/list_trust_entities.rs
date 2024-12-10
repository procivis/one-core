use crate::dto::{ListTrustEntitiesFiltersBindings, TrustEntitiesListBindingDTO};
use crate::error::BindingError;
use crate::OneCoreBinding;

#[uniffi::export]
impl OneCoreBinding {
    #[uniffi::method]
    pub fn list_trust_entities(
        &self,
        filters: ListTrustEntitiesFiltersBindings,
    ) -> Result<TrustEntitiesListBindingDTO, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .trust_entity_service
                .list_trust_entities(filters.try_into()?)
                .await?
                .into())
        })
    }
}
