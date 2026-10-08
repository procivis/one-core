use std::collections::{HashMap, HashSet};

use anyhow::anyhow;
use autometrics::autometrics;
use one_core::model::claim::Claim;
use one_core::model::relation::{BatchModelLoader, Related};
use one_core::repository::claim_repository::ClaimRepository;
use one_core::repository::error::{DataLayerError, EntityKind};
use sea_orm::sea_query::{Expr, ExprTrait, Query};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, FromQueryResult, IntoActiveModel, JoinType,
    QueryFilter, QueryOrder, QuerySelect, RelationTrait, Set, TryIntoModel,
};
use shared_types::{ClaimId, CredentialId};

use super::ClaimProvider;
use crate::claim::mapper::claim_from_model;
use crate::entity::{claim, claim_schema, credential, credential_claim, proof_claim};
use crate::mapper::to_data_layer_error;

#[autometrics]
#[async_trait::async_trait]
impl ClaimRepository for ClaimProvider {
    async fn create_claim_list(
        &self,
        credential_id: CredentialId,
        claims: Vec<Claim>,
    ) -> Result<(), DataLayerError> {
        if claims.is_empty() {
            return Ok(());
        }
        let models: Vec<claim::Model> = claims
            .into_iter()
            .map(|claim| claim::ActiveModel::from(claim).try_into_model())
            .collect::<Result<_, _>>()
            .map_err(to_data_layer_error)?;
        self.db
            .tx(async {
                lock_credential_for_claim_changes(&self.db, credential_id).await?;
                insert_missing_claims(&self.db, &models).await?;
                validate_stored_claim_contents(&self.db, &models).await?;
                validate_unique_claim_paths(&self.db, credential_id, &models).await?;
                associate_claims_with_credential(&self.db, credential_id, &models).await
            })
            .await?
    }

    async fn delete_claims_for_credential(
        &self,
        request: CredentialId,
    ) -> Result<(), DataLayerError> {
        self.delete_claims_for_credentials(HashSet::from([request]))
            .await
    }

    async fn delete_claims_for_credentials(
        &self,
        request: HashSet<CredentialId>,
    ) -> Result<(), DataLayerError> {
        self.db
            .tx(async {
                // Lock credentials in ascending ID order to reduce deadlocks
                // between operations that detach overlapping credential sets.
                credential::Entity::find()
                    .filter(credential::Column::Id.is_in(request.iter().copied()))
                    .order_by_asc(credential::Column::Id)
                    .lock_exclusive()
                    .all(&self.db)
                    .await
                    .map_err(to_data_layer_error)?;
                let associations = credential_claim::Entity::find()
                    .filter(credential_claim::Column::CredentialId.is_in(request.iter().copied()))
                    .all(&self.db)
                    .await
                    .map_err(to_data_layer_error)?;
                credential_claim::Entity::delete_many()
                    .filter(credential_claim::Column::CredentialId.is_in(request))
                    .exec(&self.db)
                    .await
                    .map_err(to_data_layer_error)?;
                let ids: Vec<_> = associations
                    .into_iter()
                    .map(|association| association.claim_id)
                    .collect();
                delete_orphan_claims(&self.db, &ids).await
            })
            .await?
    }

    async fn get_claim_list(&self, ids: Vec<ClaimId>) -> Result<Vec<Claim>, DataLayerError> {
        let claims_cnt = ids.len();
        let claim_id_to_index: HashMap<shared_types::ClaimId, usize> = ids
            .into_iter()
            .enumerate()
            .map(|(index, id)| (id, index))
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

        #[allow(clippy::indexing_slicing)]
        models.sort_by_key(|model| claim_id_to_index[&model.id]);

        // A single loader shared by all returned claims: the claim schemas are fetched lazily, but
        // when they are, it happens with one query for the whole batch.
        let schema_loader = BatchModelLoader::new(
            models.iter().map(|model| model.claim_schema_id),
            self.claim_schema_repository.clone(),
        );

        Ok(models
            .into_iter()
            .map(|model| {
                let schema = Related::new(model.claim_schema_id, schema_loader.clone());
                claim_from_model(model, schema)
            })
            .collect())
    }

    async fn get_claims_for_credential(
        &self,
        credential_id: CredentialId,
    ) -> Result<Vec<Claim>, DataLayerError> {
        #[derive(FromQueryResult)]
        struct ClaimIdModel {
            pub id: ClaimId,
        }

        let ids: Vec<ClaimId> = claim::Entity::find()
            .select_only()
            .columns([claim::Column::Id])
            .join(JoinType::InnerJoin, claim::Relation::CredentialClaim.def())
            .filter(credential_claim::Column::CredentialId.eq(credential_id))
            .join(JoinType::InnerJoin, claim::Relation::ClaimSchema.def())
            .join(
                JoinType::InnerJoin,
                claim_schema::Relation::CredentialSchema.def(),
            )
            // sorting claims according to the order from credential_schema
            .order_by_asc(claim_schema::Column::Order)
            .into_model::<ClaimIdModel>()
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?
            .into_iter()
            .map(|claim| claim.id)
            .collect();

        self.get_claim_list(ids).await
    }
}

/// Serialize association changes so concurrent writes cannot duplicate a credential's paths.
async fn lock_credential_for_claim_changes(
    connection: &impl ConnectionTrait,
    credential_id: CredentialId,
) -> Result<(), DataLayerError> {
    if credential::Entity::find_by_id(credential_id)
        .lock_exclusive()
        .one(connection)
        .await
        .map_err(to_data_layer_error)?
        .is_none()
    {
        return Err(DataLayerError::EntityNotFound {
            kind: EntityKind::Credential,
            id: credential_id.into(),
        });
    }
    Ok(())
}

/// Insert new claim IDs while preserving every field of existing rows.
async fn insert_missing_claims(
    connection: &impl ConnectionTrait,
    models: &[claim::Model],
) -> Result<(), DataLayerError> {
    let existing_ids: HashSet<ClaimId> = claim::Entity::find()
        .select_only()
        .column(claim::Column::Id)
        .filter(claim::Column::Id.is_in(models.iter().map(|claim| claim.id)))
        .into_tuple()
        .all(connection)
        .await
        .map_err(to_data_layer_error)?
        .into_iter()
        .collect();
    let missing: Vec<_> = models
        .iter()
        .filter(|claim| !existing_ids.contains(&claim.id))
        .map(|claim| claim.clone().into_active_model())
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    // A concurrent caller may still insert an ID after the lookup. Validate the
    // stored contents afterward, while avoiding MySQL no-op updates on reused rows.
    claim::Entity::insert_many(missing)
        .on_conflict_do_nothing()
        .exec_without_returning(connection)
        .await
        .map_err(to_data_layer_error)?;
    Ok(())
}

/// Reject requests that reuse an ID for different contents. ON CONFLICT DO NOTHING
/// preserves stored rows but does not report a conflicting payload.
async fn validate_stored_claim_contents(
    connection: &impl ConnectionTrait,
    models: &[claim::Model],
) -> Result<(), DataLayerError> {
    let stored: HashMap<_, _> = claim::Entity::find()
        .filter(claim::Column::Id.is_in(models.iter().map(|claim| claim.id)))
        .all(connection)
        .await
        .map_err(to_data_layer_error)?
        .into_iter()
        .map(|claim| (claim.id, claim))
        .collect();
    if models.iter().any(|claim| {
        stored.get(&claim.id).is_none_or(|stored| {
            stored.claim_schema_id != claim.claim_schema_id
                || stored.value != claim.value
                || stored.path != claim.path
                || stored.selectively_disclosable != claim.selectively_disclosable
        })
    }) {
        return Err(DataLayerError::AlreadyExists(anyhow!(
            "Claim ID conflicts with stored contents"
        )));
    }
    Ok(())
}

/// Keep one claim ID per path across existing and requested credential associations.
async fn validate_unique_claim_paths(
    connection: &impl ConnectionTrait,
    credential_id: CredentialId,
    models: &[claim::Model],
) -> Result<(), DataLayerError> {
    let existing = claim::Entity::find()
        .join(JoinType::InnerJoin, claim::Relation::CredentialClaim.def())
        .filter(credential_claim::Column::CredentialId.eq(credential_id))
        .all(connection)
        .await
        .map_err(to_data_layer_error)?;
    let mut paths = HashMap::new();
    for claim in existing.iter().chain(models) {
        if paths
            .insert(&claim.path, claim.id)
            .is_some_and(|id| id != claim.id)
        {
            return Err(DataLayerError::AlreadyExists(anyhow!(
                "Multiple claim IDs use the same credential path"
            )));
        }
    }
    Ok(())
}

/// Ignore duplicate (credential_id, claim_id) pairs; either ID may occur in other pairs.
async fn associate_claims_with_credential(
    connection: &impl ConnectionTrait,
    credential_id: CredentialId,
    models: &[claim::Model],
) -> Result<(), DataLayerError> {
    credential_claim::Entity::insert_many(models.iter().map(|claim| {
        credential_claim::ActiveModel {
            credential_id: Set(credential_id),
            claim_id: Set(claim.id),
        }
    }))
    // Derive the composite conflict key and MySQL's no-op update from the entity.
    .on_conflict_do_nothing()
    .exec_without_returning(connection)
    .await
    .map_err(to_data_layer_error)?;
    Ok(())
}

/// Remove only candidate claims whose last credential and proof references are gone.
/// Call within the transaction that removes the corresponding associations.
pub(crate) async fn delete_orphan_claims(
    connection: &impl ConnectionTrait,
    ids: &[ClaimId],
) -> Result<(), DataLayerError> {
    if ids.is_empty() {
        return Ok(());
    }
    // EXISTS only checks whether a matching row exists; the selected value is unused.
    // COUNT(*) would always return a row, even when there are no references.
    let credential_references = Query::select()
        .expr(Expr::value(1))
        .from(credential_claim::Entity)
        .and_where(
            Expr::col((credential_claim::Entity, credential_claim::Column::ClaimId))
                .equals((claim::Entity, claim::Column::Id)),
        )
        .to_owned();
    let proof_references = Query::select()
        .expr(Expr::value(1))
        .from(proof_claim::Entity)
        .and_where(
            Expr::col((proof_claim::Entity, proof_claim::Column::ClaimId))
                .equals((claim::Entity, claim::Column::Id)),
        )
        .to_owned();
    claim::Entity::delete_many()
        .filter(claim::Column::Id.is_in(ids.iter().copied()))
        .filter(Expr::exists(credential_references).not())
        .filter(Expr::exists(proof_references).not())
        .exec(connection)
        .await
        .map_err(to_data_layer_error)?;
    Ok(())
}
