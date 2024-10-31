use std::sync::Arc;

use anyhow::Context;
use one_core::model::claim::Claim;
use one_core::model::did::{Did, DidRelations};
use one_core::model::history::{History, HistoryAction, HistoryEntityType};
use one_core::model::interaction::{InteractionId, InteractionRelations};
use one_core::model::organisation::Organisation;
use one_core::model::proof::{
    GetProofList, GetProofQuery, Proof, ProofRelations, ProofState, ProofStateEnum,
    UpdateProofRequest,
};
use one_core::model::proof_schema::ProofSchemaRelations;
use one_core::repository::error::DataLayerError;
use one_core::repository::history_repository::HistoryRepository;
use one_core::repository::proof_repository::ProofRepository;
use shared_types::ProofId;
use time::OffsetDateTime;
use uuid::Uuid;

pub struct ProofHistoryDecorator {
    pub history_repository: Arc<dyn HistoryRepository>,
    pub inner: Arc<dyn ProofRepository>,
}

impl ProofHistoryDecorator {
    async fn get_organisation_for_proof(
        &self,
        proof_id: &ProofId,
    ) -> Result<Organisation, DataLayerError> {
        let proof = self
            .inner
            .get_proof(
                proof_id,
                &ProofRelations {
                    schema: Some(ProofSchemaRelations {
                        organisation: Some(Default::default()),
                        ..Default::default()
                    }),
                    interaction: Some(InteractionRelations {
                        organisation: Some(Default::default()),
                    }),
                    holder_did: Some(DidRelations {
                        organisation: Some(Default::default()),
                        ..Default::default()
                    }),
                    verifier_did: Some(DidRelations {
                        organisation: Some(Default::default()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await?
            .context("proof is missing")?;

        if let Some(organisation) = proof.schema.and_then(|schema| schema.organisation) {
            Ok(organisation)
        } else if let Some(organisation) = proof
            .interaction
            .and_then(|interaction| interaction.organisation)
        {
            Ok(organisation)
        } else if let Some(organisation) = proof.holder_did.and_then(|did| did.organisation) {
            Ok(organisation)
        } else if let Some(organisation) = proof.verifier_did.and_then(|did| did.organisation) {
            Ok(organisation)
        } else {
            Err(anyhow::anyhow!("organisation is None").into())
        }
    }
}

#[async_trait::async_trait]
impl ProofRepository for ProofHistoryDecorator {
    async fn create_proof(&self, request: Proof) -> Result<ProofId, DataLayerError> {
        self.inner.create_proof(request).await
    }

    async fn get_proof(
        &self,
        id: &ProofId,
        relations: &ProofRelations,
    ) -> Result<Option<Proof>, DataLayerError> {
        self.inner.get_proof(id, relations).await
    }

    async fn get_proof_by_interaction_id(
        &self,
        interaction_id: &InteractionId,
        relations: &ProofRelations,
    ) -> Result<Option<Proof>, DataLayerError> {
        self.inner
            .get_proof_by_interaction_id(interaction_id, relations)
            .await
    }

    async fn get_proof_list(
        &self,
        query_params: GetProofQuery,
    ) -> Result<GetProofList, DataLayerError> {
        self.inner.get_proof_list(query_params).await
    }

    async fn set_proof_state(
        &self,
        proof_id: &ProofId,
        state: ProofState,
    ) -> Result<(), DataLayerError> {
        self.inner.set_proof_state(proof_id, state.clone()).await?;

        let action = match state.state {
            ProofStateEnum::Created => HistoryAction::Created,
            ProofStateEnum::Pending => HistoryAction::Pending,
            ProofStateEnum::Requested => HistoryAction::Requested,
            ProofStateEnum::Accepted => HistoryAction::Accepted,
            ProofStateEnum::Rejected => HistoryAction::Rejected,
            ProofStateEnum::Error => HistoryAction::Errored,
        };

        let organisation = self.get_organisation_for_proof(proof_id).await?;

        let result = self
            .history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: state.created_date,
                action,
                entity_id: Some((*proof_id).into()),
                entity_type: HistoryEntityType::Proof,
                metadata: None,
                organisation: Some(organisation),
            })
            .await;

        if let Err(err) = result {
            tracing::debug!("failed to insert proof history event: {:?}", err);
        }

        Ok(())
    }

    async fn set_proof_holder_did(
        &self,
        proof_id: &ProofId,
        holder_did: Did,
    ) -> Result<(), DataLayerError> {
        self.inner.set_proof_holder_did(proof_id, holder_did).await
    }

    async fn set_proof_claims(
        &self,
        proof_id: &ProofId,
        claims: Vec<Claim>,
    ) -> Result<(), DataLayerError> {
        self.inner.set_proof_claims(proof_id, claims).await
    }

    async fn delete_proof_claims(&self, proof_id: &ProofId) -> Result<(), DataLayerError> {
        self.inner.delete_proof_claims(proof_id).await?;

        let organisation = self.get_organisation_for_proof(proof_id).await?;

        let result = self
            .history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                action: HistoryAction::ClaimsRemoved,
                entity_id: Some((*proof_id).into()),
                entity_type: HistoryEntityType::Proof,
                metadata: None,
                organisation: Some(organisation),
            })
            .await;

        if let Err(err) = result {
            tracing::debug!("failed to insert proof history event: {:?}", err);
        }

        Ok(())
    }

    async fn update_proof(
        &self,
        proof_id: &ProofId,
        proof: UpdateProofRequest,
    ) -> Result<(), DataLayerError> {
        self.inner.update_proof(proof_id, proof).await
    }
}
