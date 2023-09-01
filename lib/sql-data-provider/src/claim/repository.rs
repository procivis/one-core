use super::{mapper::try_to_claim_list, ClaimProvider};
use crate::{entity::claim, error_mapper::to_data_layer_error};
use one_core::{
    model::{
        claim::{Claim, ClaimId, ClaimRelations},
        claim_schema::ClaimSchemaId,
    },
    repository::{claim_repository::ClaimRepository, error::DataLayerError},
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use std::str::FromStr;
use uuid::Uuid;

#[async_trait::async_trait]
impl ClaimRepository for ClaimProvider {
    async fn create_claim_list(&self, claims: Vec<Claim>) -> Result<(), DataLayerError> {
        let models = claims
            .into_iter()
            .map(|item| item.try_into())
            .collect::<Result<Vec<claim::ActiveModel>, DataLayerError>>()?;

        claim::Entity::insert_many(models)
            .exec(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(())
    }

    async fn get_claim_list(
        &self,
        ids: Vec<ClaimId>,
        relations: &ClaimRelations,
    ) -> Result<Vec<Claim>, DataLayerError> {
        let ids_string: Vec<String> = ids.iter().map(|id| id.to_string()).collect();
        let models = claim::Entity::find()
            .filter(claim::Column::Id.is_in(ids_string))
            .all(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        if let Some(claim_schema_relations) = &relations.schema {
            let claim_schema_ids = models
                .iter()
                .map(|model| {
                    Uuid::from_str(&model.claim_schema_id).map_err(|_| DataLayerError::MappingError)
                })
                .collect::<Result<Vec<ClaimSchemaId>, DataLayerError>>()?;

            let claim_schemas = self
                .claim_schema_repository
                .get_claim_schema_list(claim_schema_ids, claim_schema_relations)
                .await?;

            let claims = try_to_claim_list(&ids, models)?;

            Ok(claims
                .into_iter()
                .zip(claim_schemas)
                .map(|(claim, schema)| Claim {
                    schema: Some(schema),
                    ..claim
                })
                .collect())
        } else {
            try_to_claim_list(&ids, models)
        }
    }
}
