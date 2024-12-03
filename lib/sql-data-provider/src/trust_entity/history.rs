use std::sync::Arc;

use anyhow::Context;
use one_core::model::did::DidRelations;
use one_core::model::history::{History, HistoryAction, HistoryEntityType};
use one_core::model::organisation::OrganisationRelations;
use one_core::model::trust_entity::{TrustEntity, TrustEntityRelations, UpdateTrustEntityRequest};
use one_core::repository::error::DataLayerError;
use one_core::repository::history_repository::HistoryRepository;
use one_core::repository::trust_entity_repository::TrustEntityRepository;
use one_core::service::trust_entity::dto::{
    GetTrustEntitiesResponseDTO, ListTrustEntitiesQueryDTO,
};
use shared_types::{DidId, TrustAnchorId, TrustEntityId};
use time::OffsetDateTime;
use uuid::Uuid;

pub struct TrustEntityHistoryDecorator {
    pub history_repository: Arc<dyn HistoryRepository>,
    pub inner: Arc<dyn TrustEntityRepository>,
}

#[async_trait::async_trait]
impl TrustEntityRepository for TrustEntityHistoryDecorator {
    async fn create(&self, entity: TrustEntity) -> Result<TrustEntityId, DataLayerError> {
        let trust_entity_id = self.inner.create(entity.clone()).await?;

        let result = self
            .history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: entity.created_date,
                action: HistoryAction::Created,
                entity_id: Some(trust_entity_id.into()),
                entity_type: HistoryEntityType::TrustEntity,
                metadata: None,
                organisation: entity.did.and_then(|did| did.organisation),
            })
            .await;

        if let Err(err) = result {
            tracing::debug!("failed to insert trust entity history event: {err:?}");
        }

        Ok(trust_entity_id)
    }

    async fn get_by_did_id(&self, did_id: DidId) -> Result<Option<TrustEntity>, DataLayerError> {
        self.inner.get_by_did_id(did_id).await
    }

    async fn get_by_trust_anchor_id(
        &self,
        trust_anchor_id: TrustAnchorId,
    ) -> Result<Vec<TrustEntity>, DataLayerError> {
        self.inner.get_by_trust_anchor_id(trust_anchor_id).await
    }

    async fn delete(&self, id: TrustEntityId) -> Result<(), DataLayerError> {
        let trust_entity = self
            .inner
            .get(
                id,
                &TrustEntityRelations {
                    did: Some(DidRelations {
                        organisation: Some(OrganisationRelations::default()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await?
            .context("trust entity is missing")?;

        self.inner.delete(id).await?;

        let result = self
            .history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                action: HistoryAction::Created,
                entity_id: Some(trust_entity.id.into()),
                entity_type: HistoryEntityType::TrustEntity,
                metadata: None,
                organisation: trust_entity.did.and_then(|did| did.organisation),
            })
            .await;

        if let Err(err) = result {
            tracing::debug!("failed to insert trust entity history event: {err:?}");
        }

        Ok(())
    }

    async fn get(
        &self,
        id: TrustEntityId,
        relations: &TrustEntityRelations,
    ) -> Result<Option<TrustEntity>, DataLayerError> {
        self.inner.get(id, relations).await
    }

    async fn list(
        &self,
        filters: ListTrustEntitiesQueryDTO,
    ) -> Result<GetTrustEntitiesResponseDTO, DataLayerError> {
        self.inner.list(filters).await
    }

    async fn update(
        &self,
        id: TrustEntityId,
        request: UpdateTrustEntityRequest,
    ) -> Result<(), DataLayerError> {
        self.inner.update(id, request).await
    }
}
