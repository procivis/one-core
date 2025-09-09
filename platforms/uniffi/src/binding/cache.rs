use one_dto_mapper::{From, Into};

use super::OneCoreBinding;
use crate::error::BindingError;

#[uniffi::export(async_runtime = "tokio")]
impl OneCoreBinding {
    #[uniffi::method]
    pub async fn delete_cache(
        &self,
        types: Option<Vec<CacheTypeBindingDTO>>,
    ) -> Result<(), BindingError> {
        let types = types.map(|vec| vec.into_iter().map(Into::into).collect());

        let core = self.use_core().await?;
        core.cache_service.prune_cache(types).await?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Into, From, uniffi::Enum)]
#[from("one_core::model::remote_entity_cache::CacheType")]
#[into("one_core::model::remote_entity_cache::CacheType")]
pub enum CacheTypeBindingDTO {
    DidDocument,
    JsonLdContext,
    StatusListCredential,
    VctMetadata,
    JsonSchema,
    TrustList,
    X509Crl,
    AndroidAttestationCrl,
}
