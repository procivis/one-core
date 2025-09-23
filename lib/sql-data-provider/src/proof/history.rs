use std::sync::Arc;

use anyhow::Context;
use one_core::model::claim::Claim;
use one_core::model::history::{
    History, HistoryAction, HistoryEntityType, HistoryErrorMetadata, HistoryMetadata,
};
use one_core::model::interaction::{InteractionId, InteractionRelations};
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

use crate::proof::mapper::{organisation_id_from_proof, target_from_proof};

pub struct ProofHistoryDecorator {
    pub history_repository: Arc<dyn HistoryRepository>,
    pub inner: Arc<dyn ProofRepository>,
}

impl ProofHistoryDecorator {
    async fn write_history_infallible(
        &self,
        proof_id: &ProofId,
        proof_schema_name: String,
        action: HistoryAction,
        error_info: Option<HistoryErrorMetadata>,
    ) {
        let history_result = self
            .write_history(proof_id, proof_schema_name, action, error_info)
            .await;
        if let Err(err) = history_result {
            tracing::warn!("failed to insert proof history event: {err:?}");
        }
    }
    async fn write_history(
        &self,
        proof_id: &ProofId,
        proof_schema_name: String,
        action: HistoryAction,
        error_info: Option<HistoryErrorMetadata>,
    ) -> Result<(), DataLayerError> {
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
                    holder_identifier: Some(Default::default()),
                    verifier_identifier: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await?
            .context("proof is missing")?;

        let organisation_id = organisation_id_from_proof(&proof)?;

        self.history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                action,
                name: proof_schema_name,
                target: target_from_proof(&proof),
                entity_id: Some((*proof_id).into()),
                entity_type: HistoryEntityType::Proof,
                metadata: error_info.map(HistoryMetadata::ErrorMetadata),
                organisation_id: Some(organisation_id),
                //TODO: pass user
                user: None,
            })
            .await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl ProofRepository for ProofHistoryDecorator {
    async fn create_proof(&self, request: Proof) -> Result<ProofId, DataLayerError> {
        let proof_schema_name = request
            .schema
            .as_ref()
            .map(|s| s.name.to_string())
            .unwrap_or_default();
        let history_action = HistoryAction::from(request.state.clone());
        let proof_id = self.inner.create_proof(request).await?;

        self.write_history(&proof_id, proof_schema_name, history_action, None)
            .await?;
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
        let proof_schema_name = get_proof_schema_name(proof_id, &*self.inner).await?;
        self.inner.delete_proof_claims(proof_id).await?;
        self.write_history_infallible(
            proof_id,
            proof_schema_name,
            HistoryAction::ClaimsRemoved,
            None,
        )
        .await;
        Ok(())
    }

    async fn delete_proof(&self, proof_id: &ProofId) -> Result<(), DataLayerError> {
        self.inner.delete_proof(proof_id).await?;
        let history_result = self
            .history_repository
            .delete_history_by_entity_id((*proof_id).into())
            .await;
        if let Err(err) = history_result {
            tracing::warn!("failed to delete history events for proof {proof_id}: {err:?}");
        }
        Ok(())
    }

    async fn update_proof(
        &self,
        proof_id: &ProofId,
        proof: UpdateProofRequest,
        error_info: Option<HistoryErrorMetadata>,
    ) -> Result<(), DataLayerError> {
        let state = proof.state.clone();

        self.inner.update_proof(proof_id, proof, None).await?;

        if let Some(state) = state {
            let proof_schema_name = get_proof_schema_name(proof_id, &*self.inner).await?;
            let action = HistoryAction::from(state);
            self.write_history_infallible(proof_id, proof_schema_name, action, error_info)
                .await;
        };
        Ok(())
    }
}

async fn get_proof_schema_name(
    proof_id: &ProofId,
    repo: &dyn ProofRepository,
) -> Result<String, DataLayerError> {
    let proof = repo
        .get_proof(
            proof_id,
            &ProofRelations {
                schema: Some(Default::default()),
                ..Default::default()
            },
        )
        .await?;

    Ok(proof
        .and_then(|p| p.schema.map(|s| s.name))
        .unwrap_or_default())
}
