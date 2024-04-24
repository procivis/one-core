use crate::entity::json_ld_context;
use crate::json_ld_context::JsonLdContextProvider;
use crate::mapper::to_data_layer_error;
use async_trait::async_trait;
use one_core::model::json_ld_context::{JsonLdContext, JsonLdContextRelations};
use one_core::repository::error::DataLayerError;
use one_core::repository::json_ld_context_repository::JsonLdContextRepository;
use sea_orm::{ActiveModelTrait, DbErr, EntityTrait};
use shared_types::JsonLdContextId;

#[async_trait]
impl JsonLdContextRepository for JsonLdContextProvider {
    async fn create_json_ld_context(
        &self,
        request: JsonLdContext,
    ) -> Result<JsonLdContextId, DataLayerError> {
        let context = json_ld_context::ActiveModel::from(request)
            .insert(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(context.id)
    }

    async fn update_json_ld_context(&self, request: JsonLdContext) -> Result<(), DataLayerError> {
        json_ld_context::ActiveModel::from(request)
            .update(&self.db)
            .await
            .map_err(|e| match e {
                DbErr::RecordNotUpdated => DataLayerError::RecordNotUpdated,
                _ => DataLayerError::Db(e.into()),
            })?;
        Ok(())
    }

    async fn get_json_ld_context(
        &self,
        id: &JsonLdContextId,
        _relations: &JsonLdContextRelations,
    ) -> Result<Option<JsonLdContext>, DataLayerError> {
        let context = json_ld_context::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        Ok(context.map(|context| context.try_into()).transpose()?)
    }
}
