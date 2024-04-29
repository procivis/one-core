use super::error::DataLayerError;
use crate::model::json_ld_context::{JsonLdContext, JsonLdContextRelations};
use shared_types::JsonLdContextId;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait JsonLdContextRepository: Send + Sync {
    async fn create_json_ld_context(
        &self,
        request: JsonLdContext,
    ) -> Result<JsonLdContextId, DataLayerError>;

    async fn delete_oldest_context(&self) -> Result<(), DataLayerError>;

    async fn get_json_ld_context(
        &self,
        id: &JsonLdContextId,
        relations: &JsonLdContextRelations,
    ) -> Result<Option<JsonLdContext>, DataLayerError>;

    async fn get_json_ld_context_by_url(
        &self,
        url: &str,
    ) -> Result<Option<JsonLdContext>, DataLayerError>;

    async fn get_repository_size(&self) -> Result<u32, DataLayerError>;

    async fn update_json_ld_context(&self, request: JsonLdContext) -> Result<(), DataLayerError>;
}
