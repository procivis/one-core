use super::{
    mapper::{create_list_response, get_proof_claim_active_model, get_proof_state_active_model},
    model::ProofListItemModel,
    ProofProvider,
};
use crate::{
    entity::{did, proof, proof_claim, proof_schema, proof_state},
    list_query::SelectWithListQuery,
};
use anyhow::anyhow;
use autometrics::autometrics;
use one_core::model::proof::UpdateProofRequest;
use one_core::{
    common_mapper::convert_inner,
    model::{
        claim::{Claim, ClaimId},
        did::Did,
        interaction::InteractionId,
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

#[autometrics]
#[async_trait::async_trait]
impl ProofRepository for ProofProvider {
    async fn create_proof(&self, request: Proof) -> Result<ProofId, DataLayerError> {
        let proof: proof::ActiveModel = request.clone().into();
        proof
            .insert(&self.db)
            .await
            .map_err(|e| match e.sql_err() {
                Some(SqlErr::UniqueConstraintViolation(_)) => DataLayerError::AlreadyExists,
                Some(_) | None => DataLayerError::Db(e.into()),
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
    ) -> Result<Option<Proof>, DataLayerError> {
        let proof_model = crate::entity::proof::Entity::find_by_id(proof_id.to_string())
            .one(&self.db)
            .await
            .map_err(|error| {
                tracing::error!(%error, %proof_id, "Error while fetching proof");
                DataLayerError::Db(error.into())
            })?;

        let Some(proof_model) = proof_model else {
            return Ok(None);
        };

        let proof = self.resolve_proof_relations(proof_model, relations).await?;

        Ok(Some(proof))
    }

    async fn get_proof_by_interaction_id(
        &self,
        interaction_id: &InteractionId,
        relations: &ProofRelations,
    ) -> Result<Option<Proof>, DataLayerError> {
        let proof_model = crate::entity::proof::Entity::find()
            .filter(proof::Column::InteractionId.eq(interaction_id.to_string()))
            .one(&self.db)
            .await
            .map_err(|e| {
                tracing::error!(
                    "Error while fetching proof with interaction {}. Error: {}",
                    interaction_id,
                    e.to_string()
                );
                DataLayerError::Db(e.into())
            })?;

        match proof_model {
            None => Ok(None),
            Some(proof_model) => {
                let proof = self.resolve_proof_relations(proof_model, relations).await?;
                Ok(Some(proof))
            }
        }
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
            .map_err(|e| DataLayerError::Db(e.into()))?;

        let proofs = query
            .into_model::<ProofListItemModel>()
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        // collect all states
        let proof_ids: Vec<String> = proofs.iter().map(|p| p.id.to_string()).collect();

        let proof_states = crate::entity::proof_state::Entity::find()
            .filter(proof_state::Column::ProofId.is_in(proof_ids))
            .order_by_desc(proof_state::Column::CreatedDate)
            .all(&self.db)
            .await
            .map_err(|e| {
                tracing::error!(
                    "Error while fetching proof states. Error: {}",
                    e.to_string()
                );
                DataLayerError::Db(e.into())
            })?;

        let mut proof_states_map: HashMap<ProofId, Vec<ProofState>> = HashMap::new();
        for proof_state in proof_states {
            let proof_id = Uuid::from_str(&proof_state.proof_id)?;
            proof_states_map
                .entry(proof_id)
                .or_default()
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
            .map_err(|e| DataLayerError::Db(e.into()))?;

        update_model.update(&self.db).await.map_err(|e| match e {
            DbErr::RecordNotUpdated => DataLayerError::RecordNotUpdated,
            _ => DataLayerError::Db(e.into()),
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
            holder_did_id: Set(Some(holder_did.id)),
            last_modified: Set(now),
            ..Default::default()
        };

        model.update(&self.db).await.map_err(|e| match e {
            DbErr::RecordNotUpdated => DataLayerError::RecordNotUpdated,
            _ => DataLayerError::Db(e.into()),
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

        proof_claim::Entity::insert_many(proof_claim_models)
            .exec(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        Ok(())
    }

    async fn update_proof(&self, proof: UpdateProofRequest) -> Result<(), DataLayerError> {
        let id = &proof.id;

        let holder_did_id = match proof.holder_did_id {
            None => Unchanged(Default::default()),
            Some(holder_did) => Set(Some(holder_did)),
        };

        let verifier_did_id = match proof.verifier_did_id {
            None => Unchanged(Default::default()),
            Some(verifier_did_id) => Set(Some(verifier_did_id)),
        };

        let interaction_id = match proof.interaction {
            None => Unchanged(Default::default()),
            Some(interaction_id) => Set(Some(interaction_id.to_string())),
        };
        let redirect_uri = match proof.redirect_uri {
            None => Unchanged(Default::default()),
            Some(redirect_uri) => Set(redirect_uri),
        };

        let update_model = proof::ActiveModel {
            id: Unchanged(id.to_string()),
            last_modified: Set(OffsetDateTime::now_utc()),
            holder_did_id,
            verifier_did_id,
            interaction_id,
            redirect_uri,
            ..Default::default()
        };

        if let Some(state) = proof.state {
            proof_state::Entity::insert(get_proof_state_active_model(id, state))
                .exec(&self.db)
                .await
                .map_err(|e| DataLayerError::Db(e.into()))?;
        }

        update_model.update(&self.db).await.map_err(|e| match e {
            DbErr::RecordNotUpdated => DataLayerError::RecordNotUpdated,
            _ => DataLayerError::Db(e.into()),
        })?;

        Ok(())
    }
}

/// produces list query declared to be used together with `into_model::<ProofListItemModel>()`
fn get_proof_list_query(query_params: &GetProofQuery) -> Select<crate::entity::proof::Entity> {
    crate::entity::proof::Entity::find()
        .select_only()
        .columns([
            proof::Column::Id,
            proof::Column::CreatedDate,
            proof::Column::LastModified,
            proof::Column::IssuanceDate,
            proof::Column::Transport,
            proof::Column::RedirectUri,
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
        // add related proof schema
        .join(
            sea_orm::JoinType::InnerJoin,
            proof::Relation::ProofSchema.def(),
        )
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

impl ProofProvider {
    async fn resolve_proof_relations(
        &self,
        proof_model: proof::Model,
        relations: &ProofRelations,
    ) -> Result<Proof, DataLayerError> {
        let mut proof: Proof = proof_model.clone().try_into()?;

        if let Some(proof_schema_relations) = &relations.schema {
            if let Some(proof_schema_id) = proof_model.proof_schema_id {
                let proof_schema_id = Uuid::from_str(&proof_schema_id)?;
                proof.schema = Some(
                    self.proof_schema_repository
                        .get_proof_schema(&proof_schema_id, proof_schema_relations)
                        .await?
                        .ok_or(DataLayerError::MissingRequiredRelation {
                            relation: "proof-proof_schema",
                            id: proof_schema_id.to_string(),
                        })?,
                );
            }
        }

        if let Some(claim_relations) = &relations.claims {
            let proof_claims = crate::entity::proof_claim::Entity::find()
                .filter(proof_claim::Column::ProofId.eq(&proof_model.id))
                .all(&self.db)
                .await
                .map_err(|e| DataLayerError::Db(e.into()))?;

            let claim_ids = proof_claims
                .iter()
                .map(|item| Uuid::from_str(&item.claim_id))
                .collect::<Result<Vec<ClaimId>, _>>()?;

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
            if let Some(verifier_did_id) = &proof_model.verifier_did_id {
                let verifier_did = self
                    .did_repository
                    .get_did(verifier_did_id, did_relations)
                    .await?
                    .ok_or(DataLayerError::Db(anyhow!("Verifier DID not found")))?;
                proof.verifier_did = Some(verifier_did);
            }
        }

        if let Some(did_relations) = &relations.holder_did {
            if let Some(holder_did_id) = &proof_model.holder_did_id {
                let holder_did_id = self
                    .did_repository
                    .get_did(holder_did_id, did_relations)
                    .await?
                    .ok_or(DataLayerError::Db(anyhow!(
                        "Holder DID not found".to_string()
                    )))?;
                proof.holder_did = Some(holder_did_id);
            }
        }

        if let Some(_state_relations) = &relations.state {
            let proof_states = crate::entity::proof_state::Entity::find()
                .filter(proof_state::Column::ProofId.eq(&proof_model.id))
                .order_by_desc(proof_state::Column::CreatedDate)
                .all(&self.db)
                .await
                .map_err(|e| {
                    tracing::error!(
                        "Error while fetching proof {} state. Error: {}",
                        proof_model.id,
                        e.to_string()
                    );
                    DataLayerError::Db(e.into())
                })?;

            proof.state = Some(convert_inner(proof_states));
        }

        if let (Some(interaction_relations), Some(interaction_id)) =
            (&relations.interaction, proof_model.interaction_id)
        {
            let interaction_id = Uuid::from_str(&interaction_id)?;
            let interaction = self
                .interaction_repository
                .get_interaction(&interaction_id, interaction_relations)
                .await?
                .ok_or(DataLayerError::MissingRequiredRelation {
                    relation: "proof-interaction",
                    id: interaction_id.to_string(),
                })?;

            proof.interaction = Some(interaction);
        }

        Ok(proof)
    }
}
