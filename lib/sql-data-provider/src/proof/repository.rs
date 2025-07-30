use std::str::FromStr;

use anyhow::anyhow;
use autometrics::autometrics;
use one_core::model::claim::{Claim, ClaimId};
use one_core::model::history::HistoryErrorMetadata;
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

use super::ProofProvider;
use super::mapper::{
    create_list_response, get_proof_claim_active_model, needs_interaction_table_for_filter,
};
use super::model::ProofListItemModel;
use crate::entity::{identifier, proof, proof_claim, proof_schema};
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

        let (items_count, proofs) = tokio::join!(
            query.to_owned().count(&self.db),
            query.into_model::<ProofListItemModel>().all(&self.db)
        );

        let items_count = items_count.map_err(|e| DataLayerError::Db(e.into()))?;
        let proofs = proofs.map_err(|e| DataLayerError::Db(e.into()))?;

        create_list_response(proofs, limit.unwrap_or(items_count), items_count)
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
        _error_info: Option<HistoryErrorMetadata>,
    ) -> Result<(), DataLayerError> {
        let holder_identifier_id = match proof.holder_identifier_id {
            None => Unchanged(Default::default()),
            Some(identifier_id) => Set(Some(identifier_id)),
        };

        let verifier_identifier_id = match proof.verifier_identifier_id {
            None => Unchanged(Default::default()),
            Some(identifier_id) => Set(Some(identifier_id)),
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

        let requested_date = match proof.requested_date {
            None => Unchanged(Default::default()),
            Some(datetime) => Set(datetime),
        };

        let now = OffsetDateTime::now_utc();
        let mut update_model = proof::ActiveModel {
            id: Unchanged(*proof_id),
            last_modified: Set(now),
            holder_identifier_id,
            verifier_identifier_id,
            interaction_id,
            redirect_uri,
            transport,
            requested_date,
            ..Default::default()
        };

        if let Some(state) = proof.state {
            match &state {
                ProofStateEnum::Pending => update_model.requested_date = Set(Some(now)),
                ProofStateEnum::Accepted
                | ProofStateEnum::Rejected
                | ProofStateEnum::Error
                | ProofStateEnum::Retracted => update_model.completed_date = Set(Some(now)),
                _ => {}
            };
            update_model.state = Set(state.into());
        };

        update_model
            .update(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;

        Ok(())
    }

    async fn delete_proof(&self, proof_id: &ProofId) -> Result<(), DataLayerError> {
        proof::Entity::delete_by_id(proof_id)
            .exec(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;
        Ok(())
    }
}

/// produces list query declared to be used together with `into_model::<ProofListItemModel>()`
fn get_proof_list_query(query_params: &GetProofQuery) -> Select<crate::entity::proof::Entity> {
    let mut query = crate::entity::proof::Entity::find()
        .select_only()
        .columns([
            proof::Column::Id,
            proof::Column::CreatedDate,
            proof::Column::LastModified,
            proof::Column::RedirectUri,
            proof::Column::State,
            proof::Column::Role,
            proof::Column::RequestedDate,
            proof::Column::CompletedDate,
            proof::Column::Profile,
        ])
        .column_as(proof::Column::Protocol, "protocol")
        .column_as(proof::Column::Transport, "transport")
        // add related verifierIdentifier
        .join(
            sea_orm::JoinType::LeftJoin,
            proof::Relation::VerifierIdentifier.def(),
        )
        .column_as(identifier::Column::Id, "verifier_identifier_id")
        .column_as(
            identifier::Column::CreatedDate,
            "verifier_identifier_created_date",
        )
        .column_as(
            identifier::Column::LastModified,
            "verifier_identifier_last_modified",
        )
        .column_as(identifier::Column::Name, "verifier_identifier_name")
        .column_as(identifier::Column::Type, "verifier_identifier_type")
        .column_as(
            identifier::Column::IsRemote,
            "verifier_identifier_is_remote",
        )
        .column_as(identifier::Column::State, "verifier_identifier_state")
        // add related proof schema
        .join(
            sea_orm::JoinType::LeftJoin,
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
        );

    if needs_interaction_table_for_filter(query_params.filtering.as_ref()) {
        query = query.join(
            sea_orm::JoinType::LeftJoin,
            proof::Relation::Interaction.def(),
        );
    }

    query = query.with_list_query(query_params);

    if query_params.sorting.is_some() || query_params.pagination.is_some() {
        // fallback ordering
        query = query
            .order_by_desc(proof::Column::CreatedDate)
            .order_by_desc(proof::Column::Id);
    }

    query
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

        if let Some(identifier_relations) = &relations.verifier_identifier {
            if let Some(verifier_identifier_id) = &proof_model.verifier_identifier_id {
                let verifier_identifier = self
                    .identifier_repository
                    .get(*verifier_identifier_id, identifier_relations)
                    .await?
                    .ok_or(DataLayerError::Db(anyhow!("Verifier identifier not found")))?;
                proof.verifier_identifier = Some(verifier_identifier);
            }
        }

        if let Some(identifier_relations) = &relations.holder_identifier {
            if let Some(holder_identifier_id) = &proof_model.holder_identifier_id {
                let holder_identifier = self
                    .identifier_repository
                    .get(*holder_identifier_id, identifier_relations)
                    .await?
                    .ok_or(DataLayerError::Db(anyhow!("Holder identifier not found")))?;
                proof.holder_identifier = Some(holder_identifier);
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

        if let (Some(verifier_certificate_relations), Some(verifier_certificate_id)) = (
            &relations.verifier_certificate,
            proof_model.verifier_certificate_id,
        ) {
            let verifier_certificate = self
                .certificate_repository
                .get(verifier_certificate_id, verifier_certificate_relations)
                .await?
                .ok_or(DataLayerError::MissingRequiredRelation {
                    relation: "proof-verifierCertificate",
                    id: verifier_certificate_id.to_string(),
                })?;

            proof.verifier_certificate = Some(verifier_certificate);
        }

        Ok(proof)
    }
}
