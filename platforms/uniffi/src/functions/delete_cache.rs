use crate::dto::CacheTypeBindingDTO;
use crate::error::BindingError;
use crate::OneCoreBinding;

#[uniffi::export]
impl OneCoreBinding {
    #[uniffi::method]
    pub fn delete_cache(
        &self,
        types: Option<Vec<CacheTypeBindingDTO>>,
    ) -> Result<(), BindingError> {
        let types = types.map(|vec| vec.into_iter().map(Into::into).collect());

        self.block_on(async {
            let core = self.use_core().await?;
            core.cache_service.prune_cache(types).await?;
            Ok(())
        })
    }
}
