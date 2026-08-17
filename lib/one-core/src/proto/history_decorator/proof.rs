use std::sync::Arc;

use shared_types::{InteractionId, OrganisationId, ProofId};
use uuid::Uuid;

use crate::model::claim::Claim;
use crate::model::common::LockType;
use crate::model::history::{
    History, HistoryAction, HistoryEntityType, HistoryErrorMetadata, HistoryMetadata, HistorySource,
};
use crate::model::proof::{
    GetProofList, Proof, ProofListQuery, ProofRole, ProofStateEnum, UpdateProofRequest,
};
use crate::proto::session_provider::{SessionExt, SessionProvider};
use crate::repository::error::DataLayerError;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::proof_repository::ProofRepository;

pub struct ProofHistoryDecorator {
    pub history_repository: Arc<dyn HistoryRepository>,
    pub inner: Arc<dyn ProofRepository>,
    pub session_provider: Arc<dyn SessionProvider>,
}

impl ProofHistoryDecorator {
    async fn fetch_proof(&self, proof_id: &ProofId) -> Result<Proof, DataLayerError> {
        self.inner.get_proof(proof_id, None).await
    }

    async fn write_history(
        &self,
        proof: &Proof,
        action: HistoryAction,
        error_info: Option<HistoryErrorMetadata>,
    ) {
        let proof_id = proof.id;
        let organisation_id = organisation_id_from_proof(proof).await.ok().flatten();

        let target = target_from_proof(proof);
        let name = if let Some(schema) = proof.schema.as_ref() {
            if let Ok(schema) = schema.as_ref().await {
                schema.name.to_owned()
            } else {
                target.to_owned().unwrap_or_default()
            }
        } else {
            target.to_owned().unwrap_or_default()
        };

        let result = self
            .history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: crate::clock::now_utc(),
                action,
                name,
                source: HistorySource::Core,
                target,
                entity_id: Some(proof_id.into()),
                entity_type: HistoryEntityType::Proof,
                metadata: error_info.map(HistoryMetadata::ErrorMetadata),
                metadata_blob_id: None,
                organisation_id,
                user: self.session_provider.session().user(),
            })
            .await;

        if let Err(err) = result {
            tracing::warn!("failed to insert proof history event: {err:?}");
        }
    }
}

#[async_trait::async_trait]
impl ProofRepository for ProofHistoryDecorator {
    async fn create_proof(&self, request: Proof) -> Result<ProofId, DataLayerError> {
        let action = action_from_state(request.state);
        let proof_id = self.inner.create_proof(request.clone()).await?;
        self.write_history(&request, action, None).await;
        Ok(proof_id)
    }

    async fn update_proof(
        &self,
        proof_id: &ProofId,
        update: UpdateProofRequest,
        error_info: Option<HistoryErrorMetadata>,
    ) -> Result<(), DataLayerError> {
        let mut proof = self.fetch_proof(proof_id).await?;
        let old_state = proof.state;

        self.inner
            .update_proof(proof_id, update.clone(), None)
            .await?;

        // update identifiers to properly write taget
        if proof.role == ProofRole::Holder && update.verifier_identifier_id.is_some() {
            proof = self.fetch_proof(proof_id).await?;
        }

        let new_state = update.state;
        if let Some(new_state) = new_state
            && new_state != old_state
        {
            let action = action_from_state(new_state);
            self.write_history(&proof, action, error_info).await;
        };

        // updating interaction while Pending means shared
        if proof.role == ProofRole::Verifier
            && update.interaction.is_some_and(|id| id.is_some())
            && (new_state == Some(ProofStateEnum::Pending)
                || new_state.is_none() && old_state == ProofStateEnum::Pending)
        {
            self.write_history(&proof, HistoryAction::Shared, None)
                .await;
        }

        Ok(())
    }

    async fn delete_proof_claims(&self, proof_id: &ProofId) -> Result<(), DataLayerError> {
        let proof = self.fetch_proof(proof_id).await?;
        self.inner.delete_proof_claims(proof_id).await?;
        self.write_history(&proof, HistoryAction::ClaimsRemoved, None)
            .await;
        Ok(())
    }

    async fn delete_proof(&self, proof_id: &ProofId) -> Result<(), DataLayerError> {
        self.inner.delete_proof(proof_id).await?;

        // ONE-4606: when proof is hard deleted, its history is removed as well
        if let Err(error) = self
            .history_repository
            .delete_history_by_entity_id((*proof_id).into())
            .await
        {
            tracing::warn!(%error, "failed to delete history events for proof {proof_id}");
        }

        Ok(())
    }

    async fn get_proof(
        &self,
        id: &ProofId,
        lock: Option<LockType>,
    ) -> Result<Proof, DataLayerError> {
        self.inner.get_proof(id, lock).await
    }

    async fn get_proof_by_interaction_id(
        &self,
        interaction_id: &InteractionId,
    ) -> Result<Proof, DataLayerError> {
        self.inner.get_proof_by_interaction_id(interaction_id).await
    }

    async fn get_proof_list(
        &self,
        query_params: ProofListQuery,
    ) -> Result<GetProofList, DataLayerError> {
        self.inner.get_proof_list(query_params).await
    }

    async fn set_proof_claims(
        &self,
        proof_id: &ProofId,
        claims: Vec<Claim>,
    ) -> Result<(), DataLayerError> {
        self.inner.set_proof_claims(proof_id, claims).await
    }
}

fn target_from_proof(proof: &Proof) -> Option<String> {
    match proof.role {
        ProofRole::Holder => proof
            .verifier_identifier
            .as_ref()
            .map(|identifier| identifier.id_ref().to_string()),
        _ => None,
    }
}

async fn organisation_id_from_proof(
    proof: &Proof,
) -> Result<Option<OrganisationId>, DataLayerError> {
    if let Some(schema) = proof.schema.as_ref() {
        return Ok(Some(schema.as_ref().await?.organisation.id()));
    }

    if let Some(interaction) = proof.interaction.as_ref() {
        return Ok(Some(interaction.as_ref().await?.organisation.id()));
    }

    Ok(None)
}

fn action_from_state(state: ProofStateEnum) -> HistoryAction {
    match state {
        ProofStateEnum::Created => HistoryAction::Created,
        ProofStateEnum::Pending => HistoryAction::Pending,
        ProofStateEnum::Requested => HistoryAction::Requested,
        ProofStateEnum::Accepted => HistoryAction::Accepted,
        ProofStateEnum::Rejected => HistoryAction::Rejected,
        ProofStateEnum::Error => HistoryAction::Errored,
        ProofStateEnum::Retracted => HistoryAction::Retracted,
        ProofStateEnum::InteractionExpired => HistoryAction::InteractionExpired,
    }
}
