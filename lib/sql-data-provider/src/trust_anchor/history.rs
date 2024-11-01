use std::sync::Arc;

use anyhow::Context;
use one_core::model::history::{History, HistoryAction, HistoryEntityType};
use one_core::model::trust_anchor::{TrustAnchor, TrustAnchorRelations};
use one_core::repository::error::DataLayerError;
use one_core::repository::history_repository::HistoryRepository;
use one_core::repository::trust_anchor_repository::TrustAnchorRepository;
use one_core::service::trust_anchor::dto::{GetTrustAnchorsResponseDTO, ListTrustAnchorsQueryDTO};
use shared_types::TrustAnchorId;
use time::OffsetDateTime;
use uuid::Uuid;

pub struct TrustAnchorHistoryDecorator {
    pub history_repository: Arc<dyn HistoryRepository>,
    pub inner: Arc<dyn TrustAnchorRepository>,
}

#[async_trait::async_trait]
impl TrustAnchorRepository for TrustAnchorHistoryDecorator {
    async fn create(&self, anchor: TrustAnchor) -> Result<TrustAnchorId, DataLayerError> {
        let trust_anchor_id = self.inner.create(anchor.clone()).await?;

        let result = self
            .history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: anchor.created_date,
                action: HistoryAction::Created,
                entity_id: Some(trust_anchor_id.into()),
                entity_type: HistoryEntityType::TrustAnchor,
                metadata: None,
                organisation: anchor.organisation,
            })
            .await;

        if let Err(err) = result {
            tracing::debug!("failed to insert trust anchor history event: {err:?}");
        }

        Ok(trust_anchor_id)
    }

    async fn get(
        &self,
        id: TrustAnchorId,
        relations: &TrustAnchorRelations,
    ) -> Result<Option<TrustAnchor>, DataLayerError> {
        self.inner.get(id, relations).await
    }

    async fn list(
        &self,
        filters: ListTrustAnchorsQueryDTO,
    ) -> Result<GetTrustAnchorsResponseDTO, DataLayerError> {
        self.inner.list(filters).await
    }

    async fn delete(&self, id: TrustAnchorId) -> Result<(), DataLayerError> {
        let trust_anchor = self
            .inner
            .get(
                id,
                &TrustAnchorRelations {
                    organisation: Some(Default::default()),
                },
            )
            .await?
            .context("trust anchor is missing")?;

        self.inner.delete(id).await?;

        let result = self
            .history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                action: HistoryAction::Created,
                entity_id: Some(trust_anchor.id.into()),
                entity_type: HistoryEntityType::TrustAnchor,
                metadata: None,
                organisation: trust_anchor.organisation,
            })
            .await;

        if let Err(err) = result {
            tracing::debug!("failed to insert trust anchor history event: {err:?}");
        }

        Ok(())
    }
}
