use super::ClaimProvider;
use crate::{entity::claim, mapper::to_data_layer_error};
use autometrics::autometrics;
use dto_mapper::try_convert_inner;
use one_core::{
    model::{
        claim::{Claim, ClaimId, ClaimRelations},
        claim_schema::ClaimSchemaId,
    },
    repository::{claim_repository::ClaimRepository, error::DataLayerError},
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use std::{collections::HashMap, str::FromStr};
use uuid::Uuid;

#[autometrics]
#[async_trait::async_trait]
impl ClaimRepository for ClaimProvider {
    async fn create_claim_list(&self, claims: Vec<Claim>) -> Result<(), DataLayerError> {
        let models = claims
            .into_iter()
            .map(|item| item.try_into())
            .collect::<Result<Vec<claim::ActiveModel>, _>>()?;

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
        let claims_cnt = ids.len();

        let claim_id_to_index: HashMap<String, usize> = ids
            .into_iter()
            .enumerate()
            .map(|(index, id)| (id.to_string(), index))
            .collect();

        let mut models = claim::Entity::find()
            .filter(claim::Column::Id.is_in(claim_id_to_index.keys()))
            .all(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        if claims_cnt != models.len() {
            return Err(DataLayerError::IncompleteClaimsList {
                expected: claims_cnt,
                got: models.len(),
            });
        }

        models.sort_by_key(|model| claim_id_to_index[&model.id]);

        if let Some(claim_schema_relations) = &relations.schema {
            let claim_schema_ids = models
                .iter()
                .map(|model| Uuid::from_str(&model.claim_schema_id))
                .collect::<Result<Vec<ClaimSchemaId>, _>>()?;

            let claim_schemas = self
                .claim_schema_repository
                .get_claim_schema_list(claim_schema_ids, claim_schema_relations)
                .await?;

            let claims: Vec<Claim> = try_convert_inner(models)?;

            Ok(claims
                .into_iter()
                .zip(claim_schemas)
                .map(|(claim, schema)| Claim {
                    schema: Some(schema),
                    ..claim
                })
                .collect())
        } else {
            try_convert_inner(models)
        }
    }
}
