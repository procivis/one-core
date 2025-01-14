use std::str::FromStr;

use anyhow::anyhow;
use autometrics::autometrics;
use one_core::model::claim::{Claim, ClaimId};
use one_core::model::did::Did;
use one_core::model::interaction::InteractionId;
use one_core::model::proof::{
    GetProofList, GetProofQuery, Proof, ProofClaim, ProofRelations, ProofStateEnum,
    UpdateProofRequest,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::proof_repository::ProofRepository;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect, RelationTrait, Select, Set, SqlErr, Unchanged,
};
use shared_types::ProofId;
use time::OffsetDateTime;
use uuid::Uuid;

use super::mapper::{create_list_response, get_proof_claim_active_model};
use super::model::ProofListItemModel;
use super::ProofProvider;
use crate::entity::proof::ProofRequestState;
use crate::entity::{did, proof, proof_claim, proof_schema};
use crate::list_query_generic::SelectWithListQuery;
use crate::mapper::to_update_data_layer_error;

#[autometrics]
#[async_trait::async_trait]
impl ProofRepository for ProofProvider {
    async fn create_proof(&self, request: Proof) -> Result<ProofId, DataLayerError> {
        let proof: proof::ActiveModel = request.clone().try_into()?;
        proof
            .insert(&self.db)
            .await
            .map_err(|e| match e.sql_err() {
                Some(SqlErr::UniqueConstraintViolation(_)) => DataLayerError::AlreadyExists,
                Some(_) | None => DataLayerError::Db(e.into()),
            })?;

        Ok(request.id)
    }

    async fn get_proof(
        &self,
        proof_id: &ProofId,
        relations: &ProofRelations,
    ) -> Result<Option<Proof>, DataLayerError> {
        let proof_model = crate::entity::proof::Entity::find_by_id(proof_id)
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
        let limit = query_params
            .pagination
            .as_ref()
            .map(|pagination| pagination.page_size as _);

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

        create_list_response(proofs, limit.unwrap_or(items_count), items_count)
    }

    async fn set_proof_state(
        &self,
        proof_id: &ProofId,
        state: ProofStateEnum,
    ) -> Result<(), DataLayerError> {
        let now = OffsetDateTime::now_utc();

        let model = match state {
            ProofStateEnum::Pending => proof::ActiveModel {
                id: Unchanged(*proof_id),
                last_modified: Set(now),
                state: Set(state.into()),
                requested_date: Set(Some(now)),
                ..Default::default()
            },
            ProofStateEnum::Accepted => proof::ActiveModel {
                id: Unchanged(*proof_id),
                last_modified: Set(now),
                state: Set(state.into()),
                completed_date: Set(Some(now)),
                ..Default::default()
            },
            _ => proof::ActiveModel {
                id: Unchanged(*proof_id),
                last_modified: Set(now),
                state: Set(state.into()),
                ..Default::default()
            },
        };

        model
            .update(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;

        Ok(())
    }

    async fn set_proof_holder_did(
        &self,
        proof_id: &ProofId,
        holder_did: Did,
    ) -> Result<(), DataLayerError> {
        let now = OffsetDateTime::now_utc();

        let model = proof::ActiveModel {
            id: Unchanged(*proof_id),
            holder_did_id: Set(Some(holder_did.id)),
            last_modified: Set(now),
            ..Default::default()
        };

        model
            .update(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;

        Ok(())
    }

    async fn delete_proof_claims(&self, proof_id: &ProofId) -> Result<(), DataLayerError> {
        proof_claim::Entity::delete_many()
            .filter(proof_claim::Column::ProofId.eq(proof_id))
            .exec(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

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

    async fn update_proof(
        &self,
        proof_id: &ProofId,
        proof: UpdateProofRequest,
    ) -> Result<(), DataLayerError> {
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
            Some(interaction_id) => Set(interaction_id.map(Into::into)),
        };

        let redirect_uri = match proof.redirect_uri {
            None => Unchanged(Default::default()),
            Some(redirect_uri) => Set(redirect_uri),
        };

        let transport = match proof.transport {
            None => Unchanged(Default::default()),
            Some(transport) => Set(transport),
        };

        let state = match proof.state {
            None => Unchanged(ProofRequestState::Created),
            Some(state) => Set(state.into()),
        };

        let requested_date = match proof.requested_date {
            None => Unchanged(Default::default()),
            Some(datetime) => Set(datetime),
        };

        let completed_date = match proof.completed_date {
            None => Unchanged(Default::default()),
            Some(datetime) => Set(datetime),
        };

        let update_model = proof::ActiveModel {
            id: Unchanged(*proof_id),
            last_modified: Set(OffsetDateTime::now_utc()),
            holder_did_id,
            verifier_did_id,
            interaction_id,
            redirect_uri,
            transport,
            state,
            requested_date,
            completed_date,
            ..Default::default()
        };

        update_model
            .update(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;

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
            proof::Column::RedirectUri,
            proof::Column::State,
            proof::Column::RequestedDate,
            proof::Column::CompletedDate,
        ])
        .column_as(proof::Column::Exchange, "exchange")
        .column_as(proof::Column::Transport, "transport")
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
        .column_as(
            proof_schema::Column::ImportedSourceUrl,
            "schema_imported_source_url",
        )
        .column_as(
            proof_schema::Column::ExpireDuration,
            "schema_expire_duration",
        )
        .column_as(
            proof_schema::Column::OrganisationId,
            "schema_organisation_id",
        )
        .with_list_query(query_params)
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
        let mut proof: Proof = proof_model.clone().into();

        if let Some(proof_schema_relations) = &relations.schema {
            if let Some(proof_schema_id) = proof_model.proof_schema_id {
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
                .filter(proof_claim::Column::ProofId.eq(proof_model.id))
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
                let claims = self
                    .claim_repository
                    .get_claim_list(claim_ids, &claim_relations.claim)
                    .await?;

                let mut claims: Vec<ProofClaim> = claims
                    .into_iter()
                    .map(|claim| ProofClaim {
                        claim,
                        credential: None,
                    })
                    .collect();

                if let Some(credential_relations) = &claim_relations.credential {
                    for claim in claims.iter_mut() {
                        let credential = self
                            .credential_repository
                            .get_credential_by_claim_id(&claim.claim.id, credential_relations)
                            .await?
                            .ok_or(DataLayerError::Db(anyhow!("Credential not found")))?;
                        claim.credential = Some(credential);
                    }
                }

                Some(claims)
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

        if let (Some(verifier_key_relations), Some(verifier_key_id)) =
            (&relations.verifier_key, proof_model.verifier_key_id)
        {
            let verifier_key = self
                .key_repository
                .get_key(&verifier_key_id, verifier_key_relations)
                .await?
                .ok_or(DataLayerError::MissingRequiredRelation {
                    relation: "proof-verifierkey",
                    id: verifier_key_id.to_string(),
                })?;

            proof.verifier_key = Some(verifier_key);
        }

        Ok(proof)
    }
}
