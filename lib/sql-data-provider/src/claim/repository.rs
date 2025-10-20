use std::collections::{HashMap, HashSet};

use autometrics::autometrics;
use one_core::model::claim::{Claim, ClaimId, ClaimRelations};
use one_core::repository::claim_repository::ClaimRepository;
use one_core::repository::error::DataLayerError;
use one_dto_mapper::convert_inner;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use shared_types::{ClaimSchemaId, CredentialId};

use super::ClaimProvider;
use crate::entity::claim;
use crate::mapper::to_data_layer_error;

#[autometrics]
#[async_trait::async_trait]
impl ClaimRepository for ClaimProvider {
    async fn create_claim_list(&self, claims: Vec<Claim>) -> Result<(), DataLayerError> {
        let models = claims
            .into_iter()
            .map(|item| item.try_into())
            .collect::<Result<Vec<claim::ActiveModel>, _>>()?;

        claim::Entity::insert_many(models)
            .exec(&self.db.tx())
            .await
            .map_err(to_data_layer_error)?;

        Ok(())
    }

    async fn delete_claims_for_credential(
        &self,
        request: CredentialId,
    ) -> Result<(), DataLayerError> {
        claim::Entity::delete_many()
            .filter(claim::Column::CredentialId.eq(request))
            .exec(&self.db.tx())
            .await
            .map_err(to_data_layer_error)?;

        Ok(())
    }

    async fn delete_claims_for_credentials(
        &self,
        request: HashSet<CredentialId>,
    ) -> Result<(), DataLayerError> {
        claim::Entity::delete_many()
            .filter(claim::Column::CredentialId.is_in(request))
            .exec(&self.db.tx())
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
        let claim_id_to_index: HashMap<shared_types::ClaimId, usize> = ids
            .into_iter()
            .enumerate()
            .map(|(index, id)| (id.into(), index))
            .collect();

        let mut models = claim::Entity::find()
            .filter(claim::Column::Id.is_in(claim_id_to_index.keys()))
            .all(&self.db.tx())
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
                .map(|model| model.claim_schema_id)
                .collect::<Vec<ClaimSchemaId>>();
            let claim_schemas = self
                .claim_schema_repository
                .get_claim_schema_list(claim_schema_ids.clone(), claim_schema_relations)
                .await?;

            let claims: Vec<Claim> = convert_inner(models.to_owned());
            Ok(claims
                .into_iter()
                .zip(models)
                .map(|(claim, model)| {
                    let claim_schema = claim_schemas
                        .iter()
                        .find(|schema| schema.id == model.claim_schema_id)
                        .ok_or(DataLayerError::MissingClaimsSchemaForClaim(
                            model.claim_schema_id,
                            model.id,
                        ))?;

                    Ok(Claim {
                        schema: Some(claim_schema.to_owned()),
                        ..claim
                    })
                })
                .collect::<Result<Vec<_>, DataLayerError>>()?)
        } else {
            Ok(convert_inner(models))
        }
    }
}
