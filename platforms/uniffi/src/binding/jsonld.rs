use super::OneCoreBinding;
use crate::error::BindingError;

#[uniffi::export(async_runtime = "tokio")]
impl OneCoreBinding {
    #[uniffi::method]
    pub async fn resolve_jsonld_context(
        &self,
        url: String,
    ) -> Result<ResolveJsonLDContextResponseBindingDTO, BindingError> {
        let core = self.use_core().await?;
        let context = core.jsonld_service.resolve_context(url).await?;
        Ok(ResolveJsonLDContextResponseBindingDTO {
            context: context.to_string(),
        })
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ResolveJsonLDContextResponseBindingDTO {
    pub context: String,
}
