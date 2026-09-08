use autometrics::autometrics;
use one_core::model::claim::Claim;
use one_core::model::common::LockType;
use one_core::model::history::HistoryErrorMetadata;
use one_core::model::proof::{
    GetProofList, Proof, ProofListQuery, ProofStateEnum, UpdateProofRequest,
};
use one_core::repository::error::{DataLayerError, EntityKind};
use one_core::repository::proof_repository::ProofRepository;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect, RelationTrait, Select, Set, SqlErr, Unchanged,
};
use shared_types::{InteractionId, ProofId};

use super::ProofProvider;
use super::mapper::{
    create_list_response, get_proof_claim_active_model, needs_interaction_table_for_filter,
    proof_model_to_repository,
};
use super::model::ProofListItemModel;
use crate::entity::{identifier, proof, proof_claim, proof_schema};
use crate::list_query_generic::SelectWithListQuery;
use crate::mapper::{map_lock_type, to_update_data_layer_error};

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
        lock: Option<LockType>,
    ) -> Result<Proof, DataLayerError> {
        let select = proof::Entity::find_by_id(proof_id);
        let select = match lock {
            None => select,
            Some(lock) => select.lock(map_lock_type(lock)),
        };
        let proof_model = select
            .one(&self.db)
            .await
            .map_err(|error| {
                tracing::error!(%error, %proof_id, "Error while fetching proof");
                DataLayerError::Db(error.into())
            })?
            .ok_or_else(|| DataLayerError::EntityNotFound {
                kind: EntityKind::Proof,
                id: (*proof_id).into(),
            })?;

        Ok(proof_model_to_repository(
            proof_model,
            &self.credential_repository,
            &self.claim_repository,
            &self.proof_schema_repository,
            &self.identifier_repository,
            &self.key_repository,
            &self.certificate_repository,
            &self.interaction_repository,
            &self.db,
        ))
    }

    async fn get_proof_by_interaction_id(
        &self,
        interaction_id: &InteractionId,
    ) -> Result<Proof, DataLayerError> {
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
            })?
            .ok_or_else(|| DataLayerError::EntityNotFound {
                kind: EntityKind::ProofByInteraction,
                id: (*interaction_id).into(),
            })?;

        Ok(proof_model_to_repository(
            proof_model,
            &self.credential_repository,
            &self.claim_repository,
            &self.proof_schema_repository,
            &self.identifier_repository,
            &self.key_repository,
            &self.certificate_repository,
            &self.interaction_repository,
            &self.db,
        ))
    }

    async fn get_proof_list(
        &self,
        query_params: ProofListQuery,
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

        create_list_response(
            proofs,
            limit.unwrap_or(items_count),
            items_count,
            &self.organisation_repository,
            &self.did_repository,
            &self.key_repository,
            &self.certificate_repository,
            &self.trust_information_repository,
            &self.claim_repository,
            &self.credential_repository,
            &self.localized_text_repository,
            &self.db,
        )
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
            .map(|claim| get_proof_claim_active_model(*proof_id, claim))
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
        let verifier_identifier_id = match proof.verifier_identifier_id {
            None => Unchanged(Default::default()),
            Some(identifier_id) => Set(Some(identifier_id)),
        };

        let interaction_id = match proof.interaction {
            None => Unchanged(Default::default()),
            Some(interaction_id) => Set(interaction_id),
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

        let proof_blob_id = match proof.proof_blob_id {
            None => Unchanged(Default::default()),
            Some(blob_id) => Set(blob_id),
        };

        let engagement = match proof.engagement {
            None => Unchanged(Default::default()),
            Some(engagement) => Set(engagement),
        };

        let ecosystem = match proof.ecosystem {
            None => Unchanged(Default::default()),
            Some(ecosystem) => Set(ecosystem),
        };

        let now = one_core::clock::now_utc();
        let mut update_model = proof::ActiveModel {
            id: Unchanged(*proof_id),
            last_modified: Set(now),
            verifier_identifier_id,
            interaction_id,
            redirect_uri,
            transport,
            requested_date,
            proof_blob_id,
            engagement,
            ecosystem,
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
fn get_proof_list_query(query_params: &ProofListQuery) -> Select<crate::entity::proof::Entity> {
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
            proof::Column::ProofBlobId,
            proof::Column::Engagement,
            proof::Column::WebhookUrl,
            proof::Column::Protocol,
            proof::Column::Transport,
            proof::Column::Ecosystem,
        ])
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
        .column_as(
            identifier::Column::Autogenerated,
            "verifier_identifier_autogenerated",
        )
        .column_as(identifier::Column::State, "verifier_identifier_state")
        .column_as(
            identifier::Column::OrganisationId,
            "verifier_identifier_organisation_id",
        )
        .column_as(identifier::Column::DidId, "verifier_identifier_did_id")
        .column_as(identifier::Column::KeyId, "verifier_identifier_key_id")
        .column_as(identifier::Column::Logo, "verifier_identifier_logo")
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
        )
        .column_as(proof_schema::Column::Ecosystem, "schema_ecosystem");

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
