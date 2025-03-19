use std::sync::Arc;

use anyhow::Context;
use one_core::model::did::{Did, DidListQuery, DidRelations, GetDidList, UpdateDidRequest};
use one_core::model::history::{History, HistoryAction, HistoryEntityType};
use one_core::repository::did_repository::DidRepository;
use one_core::repository::error::DataLayerError;
use one_core::repository::history_repository::HistoryRepository;
use shared_types::{DidId, DidValue};
use time::OffsetDateTime;
use uuid::Uuid;

pub struct DidHistoryDecorator {
    pub history_repository: Arc<dyn HistoryRepository>,
    pub inner: Arc<dyn DidRepository>,
}

#[async_trait::async_trait]
impl DidRepository for DidHistoryDecorator {
    async fn create_did(&self, request: Did) -> Result<DidId, DataLayerError> {
        let did_id = self.inner.create_did(request.clone()).await?;

        let result = self
            .history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: request.created_date,
                action: HistoryAction::Created,
                entity_id: Some(did_id.into()),
                entity_type: HistoryEntityType::Did,
                metadata: None,
                organisation_id: request.organisation.ok_or(DataLayerError::MappingError)?.id,
            })
            .await;

        if let Err(err) = result {
            tracing::debug!("failed to insert did history event: {err:?}");
        }

        Ok(did_id)
    }

    async fn get_did(
        &self,
        id: &DidId,
        relations: &DidRelations,
    ) -> Result<Option<Did>, DataLayerError> {
        self.inner.get_did(id, relations).await
    }

    async fn get_did_by_value(
        &self,
        value: &DidValue,
        relations: &DidRelations,
    ) -> Result<Option<Did>, DataLayerError> {
        self.inner.get_did_by_value(value, relations).await
    }

    async fn get_did_list(&self, query: DidListQuery) -> Result<GetDidList, DataLayerError> {
        self.inner.get_did_list(query).await
    }

    async fn update_did(&self, request: UpdateDidRequest) -> Result<(), DataLayerError> {
        self.inner.update_did(request.clone()).await?;

        if request.deactivated.is_none() {
            return Ok(());
        };

        let did = self
            .inner
            .get_did(
                &request.id,
                &DidRelations {
                    organisation: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await?
            .context("did is missing")?;

        let result = self
            .history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                action: HistoryAction::Deactivated,
                entity_id: Some(request.id.into()),
                entity_type: HistoryEntityType::Did,
                metadata: None,
                organisation_id: did.organisation.ok_or(DataLayerError::MappingError)?.id,
            })
            .await;

        if let Err(err) = result {
            tracing::debug!("failed to insert did history event: {err:?}");
        }

        Ok(())
    }
}
