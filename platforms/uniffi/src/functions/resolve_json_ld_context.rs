use crate::binding::OneCoreBinding;
use crate::error::BindingError;
use crate::ResolveJsonLDContextResponseBindingDTO;

#[uniffi::export]
impl OneCoreBinding {
    #[uniffi::method]
    pub fn resolve_jsonld_context(
        &self,
        url: String,
    ) -> Result<ResolveJsonLDContextResponseBindingDTO, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            let context = core.jsonld_service.resolve_context(url).await?;
            Ok(ResolveJsonLDContextResponseBindingDTO {
                context: context.to_string(),
            })
        })
    }
}
