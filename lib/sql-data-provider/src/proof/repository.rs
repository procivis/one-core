use super::{
    mapper::{create_list_response, get_proof_claim_active_model, get_proof_state_active_model},
    model::ProofListItemModel,
    ProofProvider,
};
use crate::{
    entity::{did, proof, proof_claim, proof_schema, proof_state},
    list_query::SelectWithListQuery,
};
use one_core::{
    common_mapper::vector_into,
    model::{
        claim::{Claim, ClaimId},
        did::Did,
        proof::{GetProofList, GetProofQuery, Proof, ProofId, ProofRelations, ProofState},
    },
    repository::{error::DataLayerError, proof_repository::ProofRepository},
};
use sea_orm::{
    sea_query::{expr::Expr, Alias, IntoCondition, Query},
    ActiveModelTrait, ColumnTrait, DbErr, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect, RelationTrait, Select, Set, SqlErr, Unchanged,
};
use std::{collections::HashMap, str::FromStr};
use time::OffsetDateTime;
use uuid::Uuid;

#[async_trait::async_trait]
impl ProofRepository for ProofProvider {
    async fn create_proof(&self, request: Proof) -> Result<ProofId, DataLayerError> {
        let proof: proof::ActiveModel = request.clone().try_into()?;
        proof
            .insert(&self.db)
            .await
            .map_err(|e| match e.sql_err() {
                Some(sql_error) if matches!(sql_error, SqlErr::UniqueConstraintViolation(_)) => {
                    DataLayerError::AlreadyExists
                }
                Some(sql_error)
                    if matches!(sql_error, SqlErr::ForeignKeyConstraintViolation(_)) =>
                {
                    DataLayerError::RecordNotFound
                }
                Some(_) | None => DataLayerError::GeneralRuntimeError(e.to_string()),
            })?;

        if let Some(states) = request.state {
            for state in states {
                self.set_proof_state(&request.id, state).await?;
            }
        }

        Ok(request.id)
    }

    async fn get_proof(
        &self,
        proof_id: &ProofId,
        relations: &ProofRelations,
    ) -> Result<Proof, DataLayerError> {
        let proof_model = crate::entity::Proof::find_by_id(proof_id.to_string())
            .one(&self.db)
            .await
            .map_err(|e| {
                tracing::error!(
                    "Error while fetching proof {}. Error: {}",
                    proof_id,
                    e.to_string()
                );
                DataLayerError::GeneralRuntimeError(e.to_string())
            })?
            .ok_or(DataLayerError::RecordNotFound)?;

        let mut proof: Proof = proof_model.clone().try_into()?;

        if let Some(proof_schema_relations) = &relations.schema {
            let proof_schema_id = Uuid::from_str(&proof_model.proof_schema_id)
                .map_err(|_| DataLayerError::MappingError)?;
            proof.schema = Some(
                self.proof_schema_repository
                    .get_proof_schema(&proof_schema_id, proof_schema_relations)
                    .await?,
            );
        }

        if let Some(claim_relations) = &relations.claims {
            let proof_claims = crate::entity::ProofClaim::find()
                .filter(proof_claim::Column::ProofId.eq(proof_id.to_string()))
                .all(&self.db)
                .await
                .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

            let claim_ids = proof_claims
                .iter()
                .map(|item| Uuid::from_str(&item.claim_id))
                .collect::<Result<Vec<ClaimId>, _>>()
                .map_err(|_| DataLayerError::MappingError)?;

            proof.claims = if claim_ids.is_empty() {
                Some(vec![])
            } else {
                Some(
                    self.claim_repository
                        .get_claim_list(claim_ids, claim_relations)
                        .await?,
                )
            };
        }

        if let Some(did_relations) = &relations.verifier_did {
            let verifier_did_id = Uuid::from_str(&proof_model.verifier_did_id)
                .map_err(|_| DataLayerError::MappingError)?;

            proof.verifier_did = Some(
                self.did_repository
                    .get_did(&verifier_did_id, did_relations)
                    .await?,
            );
        }

        if let Some(did_relations) = &relations.holder_did {
            if let Some(holder_did_id) = &proof_model.holder_did_id {
                let holder_did_id =
                    Uuid::from_str(holder_did_id).map_err(|_| DataLayerError::MappingError)?;

                proof.holder_did = Some(
                    self.did_repository
                        .get_did(&holder_did_id, did_relations)
                        .await?,
                );
            }
        }

        if let Some(_state_relations) = &relations.state {
            let proof_states = crate::entity::ProofState::find()
                .filter(proof_state::Column::ProofId.eq(proof_id.to_string()))
                .order_by_desc(proof_state::Column::CreatedDate)
                .all(&self.db)
                .await
                .map_err(|e| {
                    tracing::error!(
                        "Error while fetching proof {} state. Error: {}",
                        proof_id,
                        e.to_string()
                    );
                    DataLayerError::GeneralRuntimeError(e.to_string())
                })?;

            proof.state = Some(vector_into(proof_states));
        }

        Ok(proof)
    }

    async fn get_proof_list(
        &self,
        query_params: GetProofQuery,
    ) -> Result<GetProofList, DataLayerError> {
        let limit: u64 = query_params.page_size as u64;

        let query = get_proof_list_query(&query_params);

        let items_count = query
            .to_owned()
            .count(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        let proofs = query
            .into_model::<ProofListItemModel>()
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        // collect all states
        let proof_ids: Vec<String> = proofs.iter().map(|p| p.id.to_string()).collect();
        let proof_states = crate::entity::ProofState::find()
            .filter(proof_state::Column::ProofId.is_in(proof_ids))
            .order_by_desc(proof_state::Column::CreatedDate)
            .all(&self.db)
            .await
            .map_err(|e| {
                tracing::error!(
                    "Error while fetching proof states. Error: {}",
                    e.to_string()
                );
                DataLayerError::GeneralRuntimeError(e.to_string())
            })?;

        let mut proof_states_map: HashMap<ProofId, Vec<ProofState>> = HashMap::new();
        for proof_state in proof_states {
            let proof_id =
                Uuid::from_str(&proof_state.proof_id).map_err(|_| DataLayerError::MappingError)?;
            proof_states_map
                .entry(proof_id)
                .or_insert(vec![])
                .push(proof_state.into());
        }

        create_list_response(proofs, proof_states_map, limit, items_count)
    }

    async fn set_proof_state(
        &self,
        proof_id: &ProofId,
        state: ProofState,
    ) -> Result<(), DataLayerError> {
        let update_model = proof::ActiveModel {
            id: Unchanged(proof_id.to_string()),
            last_modified: Set(state.last_modified),
            ..Default::default()
        };

        proof_state::Entity::insert(get_proof_state_active_model(proof_id, state))
            .exec(&self.db)
            .await
            .map_err(|e| match e.sql_err() {
                Some(SqlErr::ForeignKeyConstraintViolation(_)) => DataLayerError::RecordNotFound,
                _ => DataLayerError::GeneralRuntimeError(e.to_string()),
            })?;

        update_model.update(&self.db).await.map_err(|e| match e {
            DbErr::RecordNotUpdated => DataLayerError::RecordNotUpdated,
            _ => DataLayerError::GeneralRuntimeError(e.to_string()),
        })?;

        Ok(())
    }

    async fn set_proof_holder_did(
        &self,
        proof_id: &ProofId,
        holder_did: Did,
    ) -> Result<(), DataLayerError> {
        let now = OffsetDateTime::now_utc();

        let model = proof::ActiveModel {
            id: Unchanged(proof_id.to_string()),
            holder_did_id: Set(Some(holder_did.id.to_string())),
            last_modified: Set(now),
            ..Default::default()
        };

        model.update(&self.db).await.map_err(|e| match e {
            DbErr::RecordNotUpdated => DataLayerError::RecordNotUpdated,
            _ => DataLayerError::GeneralRuntimeError(e.to_string()),
        })?;

        Ok(())
    }

    async fn set_proof_claims(
        &self,
        proof_id: &ProofId,
        claims: Vec<Claim>,
    ) -> Result<(), DataLayerError> {
        let proof_claim_models: Vec<proof_claim::ActiveModel> = claims
            .iter()
            .map(|claim| get_proof_claim_active_model(proof_id, claim))
            .collect();

        self.claim_repository.create_claim_list(claims).await?;

        proof_claim::Entity::insert_many(proof_claim_models)
            .exec(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        Ok(())
    }
}

/// produces list query declared to be used together with `into_model::<ProofListItemModel>()`
fn get_proof_list_query(query_params: &GetProofQuery) -> Select<crate::entity::Proof> {
    crate::entity::Proof::find()
        .select_only()
        .columns([
            proof::Column::Id,
            proof::Column::CreatedDate,
            proof::Column::LastModified,
            proof::Column::IssuanceDate,
            proof::Column::Transport,
        ])
        // add related verifierDid
        .join(
            sea_orm::JoinType::LeftJoin,
            proof::Relation::VerifierDid.def(),
        )
        .column_as(did::Column::Id, "verifier_did_id")
        .column_as(did::Column::Did, "verifier_did")
        .column_as(did::Column::CreatedDate, "verifier_did_created_date")
        .column_as(did::Column::LastModified, "verifier_did_last_modified")
        .column_as(did::Column::Name, "verifier_did_name")
        .column_as(did::Column::TypeField, "verifier_did_type")
        .column_as(did::Column::Method, "verifier_did_method")
        .column_as(did::Column::OrganisationId, "organisation_id")
        // add related proof schema
        .join(
            sea_orm::JoinType::InnerJoin,
            proof::Relation::ProofSchema.def(),
        )
        .filter(proof_schema::Column::DeletedAt.is_null())
        .column_as(proof_schema::Column::Id, "schema_id")
        .column_as(proof_schema::Column::Name, "schema_name")
        .column_as(proof_schema::Column::CreatedDate, "schema_created_date")
        .column_as(proof_schema::Column::LastModified, "schema_last_modified")
        .column_as(proof_schema::Column::ExpireDuration, "expire_duration")
        // find most recent state (to enable sorting)
        .join(
            sea_orm::JoinType::InnerJoin,
            proof::Relation::ProofState.def(),
        )
        .filter(
            proof_state::Column::CreatedDate
                .in_subquery(
                    Query::select()
                        .expr(
                            Expr::col((
                                Alias::new("inner_state"),
                                proof_state::Column::CreatedDate,
                            ))
                            .max(),
                        )
                        .from_as(proof_state::Entity, Alias::new("inner_state"))
                        .cond_where(
                            Expr::col((Alias::new("inner_state"), proof_state::Column::ProofId))
                                .equals((proof_state::Entity, proof_state::Column::ProofId)),
                        )
                        .to_owned(),
                )
                .into_condition(),
        )
        // apply query params
        .with_list_query(query_params, &Some(vec![proof_schema::Column::Name]))
        .with_organisation_id(query_params, &proof_schema::Column::OrganisationId)
        // fallback ordering
        .order_by_desc(proof::Column::CreatedDate)
        .order_by_desc(proof::Column::Id)
}
