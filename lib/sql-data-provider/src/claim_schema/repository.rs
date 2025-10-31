use std::collections::HashMap;

use autometrics::autometrics;
use itertools::Itertools;
use one_core::model::claim_schema::{ClaimSchema, ClaimSchemaRelations};
use one_core::repository::claim_schema_repository::ClaimSchemaRepository;
use one_core::repository::error::DataLayerError;
use one_dto_mapper::convert_inner;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use shared_types::ClaimSchemaId;

use super::ClaimSchemaProvider;
use crate::entity::claim_schema;
use crate::mapper::to_data_layer_error;

#[autometrics]
#[async_trait::async_trait]
impl ClaimSchemaRepository for ClaimSchemaProvider {
    async fn create_claim_schema_list(
        &self,
        claim_schemas: Vec<ClaimSchema>,
    ) -> Result<(), DataLayerError> {
        let models: Vec<claim_schema::ActiveModel> = convert_inner(claim_schemas);

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
        let claim_schema_cnt = ids.iter().unique().count();
        let claim_schema_to_index: HashMap<ClaimSchemaId, usize> = ids
            .into_iter()
            .enumerate()
            .map(|(index, id)| (id, index))
            .collect();

        let claim_schema_ids = claim_schema_to_index.keys().map(ToString::to_string);
        let models = claim_schema::Entity::find()
            .filter(claim_schema::Column::Id.is_in(claim_schema_ids))
            .all(&self.db)
            .await
            .map_err(|err| DataLayerError::Db(err.into()))?;

        if claim_schema_cnt != models.len() {
            return Err(DataLayerError::IncompleteClaimsSchemaList {
                expected: claim_schema_cnt,
                got: models.len(),
            });
        }

        let mut claim_schema_list: Vec<ClaimSchema> = convert_inner(models);

        claim_schema_list.sort_by_key(|claim_schema| claim_schema_to_index[&claim_schema.id]);

        Ok(claim_schema_list)
    }
}
