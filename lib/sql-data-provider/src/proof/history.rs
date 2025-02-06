use std::sync::Arc;

use anyhow::Context;
use one_core::model::claim::Claim;
use one_core::model::did::DidRelations;
use one_core::model::history::{History, HistoryAction, HistoryEntityType};
use one_core::model::interaction::{InteractionId, InteractionRelations};
use one_core::model::organisation::Organisation;
use one_core::model::proof::{
    GetProofList, GetProofQuery, Proof, ProofRelations, UpdateProofRequest,
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

    async fn write_history_entry(
        &self,
        proof_id: &ProofId,
        action: HistoryAction,
    ) -> Result<(), DataLayerError> {
        let organisation = self.get_organisation_for_proof(proof_id).await?;

        let result = self
            .history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                action,
                entity_id: Some((*proof_id).into()),
                entity_type: HistoryEntityType::Proof,
                metadata: None,
                organisation: Some(organisation),
            })
            .await;

        if let Err(err) = result {
            tracing::debug!("failed to insert proof history event: {err:?}");
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl ProofRepository for ProofHistoryDecorator {
    async fn create_proof(&self, request: Proof) -> Result<ProofId, DataLayerError> {
        let history_action = HistoryAction::from(request.state.clone());
        let proof_id = self.inner.create_proof(request).await?;
        self.write_history_entry(&proof_id, history_action).await?;
        Ok(proof_id)
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

    async fn set_proof_claims(
        &self,
        proof_id: &ProofId,
        claims: Vec<Claim>,
    ) -> Result<(), DataLayerError> {
        self.inner.set_proof_claims(proof_id, claims).await
    }

    async fn delete_proof_claims(&self, proof_id: &ProofId) -> Result<(), DataLayerError> {
        self.inner.delete_proof_claims(proof_id).await?;
        self.write_history_entry(proof_id, HistoryAction::ClaimsRemoved)
            .await?;
        Ok(())
    }

    async fn update_proof(
        &self,
        proof_id: &ProofId,
        proof: UpdateProofRequest,
    ) -> Result<(), DataLayerError> {
        if let Some(ref state) = proof.state {
            self.write_history_entry(proof_id, HistoryAction::from(state.clone()))
                .await?;
        }
        self.inner.update_proof(proof_id, proof).await
    }
}
