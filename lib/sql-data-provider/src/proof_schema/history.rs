use std::sync::Arc;

use anyhow::{Context, anyhow};
use one_core::model::history::{History, HistoryAction, HistoryEntityType};
use one_core::model::organisation::Organisation;
use one_core::model::proof_schema::{
    GetProofSchemaList, GetProofSchemaQuery, ProofSchema, ProofSchemaRelations,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::history_repository::HistoryRepository;
use one_core::repository::proof_schema_repository::ProofSchemaRepository;
use shared_types::{OrganisationId, ProofSchemaId};
use time::OffsetDateTime;
use uuid::Uuid;

pub struct ProofSchemaHistoryDecorator {
    pub history_repository: Arc<dyn HistoryRepository>,
    pub inner: Arc<dyn ProofSchemaRepository>,
}

impl ProofSchemaHistoryDecorator {
    async fn get_organisation_for_proof_schema(
        &self,
        proof_schema_id: &ProofSchemaId,
    ) -> Result<Organisation, DataLayerError> {
        let proof_schema = self
            .inner
            .get_proof_schema(
                proof_schema_id,
                &ProofSchemaRelations {
                    organisation: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await?
            .context("proof schema is missing")?;

        proof_schema
            .organisation
            .ok_or_else(|| anyhow::anyhow!("organisation is None").into())
    }

    async fn insert_history(
        &self,
        id: ProofSchemaId,
        name: String,
        organisation_id: OrganisationId,
        action: HistoryAction,
    ) {
        if let Err(error) = self
            .history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                action,
                name,
                target: None,
                entity_id: Some(id.into()),
                entity_type: HistoryEntityType::ProofSchema,
                metadata: None,
                organisation_id,
            })
            .await
        {
            tracing::warn!(%error, "failed to insert proof schema history event");
        }
    }
}

#[async_trait::async_trait]
impl ProofSchemaRepository for ProofSchemaHistoryDecorator {
    async fn create_proof_schema(
        &self,
        request: ProofSchema,
    ) -> Result<ProofSchemaId, DataLayerError> {
        self.inner.create_proof_schema(request).await
    }

    async fn get_proof_schema(
        &self,
        id: &ProofSchemaId,
        relations: &ProofSchemaRelations,
    ) -> Result<Option<ProofSchema>, DataLayerError> {
        self.inner.get_proof_schema(id, relations).await
    }

    async fn get_proof_schema_list(
        &self,
        query_params: GetProofSchemaQuery,
    ) -> Result<GetProofSchemaList, DataLayerError> {
        self.inner.get_proof_schema_list(query_params).await
    }

    async fn delete_proof_schema(
        &self,
        id: &ProofSchemaId,
        deleted_at: OffsetDateTime,
    ) -> Result<(), DataLayerError> {
        self.inner.delete_proof_schema(id, deleted_at).await?;
        let proof_schema = self
            .inner
            .get_proof_schema(id, &ProofSchemaRelations::default())
            .await?
            .ok_or_else(|| {
                DataLayerError::Db(anyhow!("We cannot find proof schema we just updated: {id}"))
            })?;
        let organisation = self.get_organisation_for_proof_schema(id).await?;

        self.insert_history(
            *id,
            proof_schema.name,
            organisation.id,
            HistoryAction::Deleted,
        )
        .await;

        Ok(())
    }
}
