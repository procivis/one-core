use one_core::{
    model::claim_schema::{ClaimSchema, ClaimSchemaId, ClaimSchemaRelations},
    repository::{claim_schema_repository::ClaimSchemaRepository, error::DataLayerError},
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

use crate::{entity::claim_schema, error_mapper::to_data_layer_error};

use super::{mapper::to_claim_schema_list, ClaimSchemaProvider};

#[async_trait::async_trait]
impl ClaimSchemaRepository for ClaimSchemaProvider {
    async fn create_claim_schema_list(
        &self,
        claim_schemas: Vec<ClaimSchema>,
    ) -> Result<(), DataLayerError> {
        let models: Vec<claim_schema::ActiveModel> =
            claim_schemas.into_iter().map(Into::into).collect();

        claim_schema::Entity::insert_many(models)
            .exec(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(())
    }

    async fn get_claim_schema_list(
        &self,
        ids: Vec<ClaimSchemaId>,
        _relations: &ClaimSchemaRelations,
    ) -> Result<Vec<ClaimSchema>, DataLayerError> {
        let ids_string: Vec<String> = ids.iter().map(|id| id.to_string()).collect();
        let models = claim_schema::Entity::find()
            .filter(claim_schema::Column::Id.is_in(ids_string))
            .all(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(to_claim_schema_list(&ids, models))
    }
}
