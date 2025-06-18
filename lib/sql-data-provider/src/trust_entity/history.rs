use std::sync::Arc;

use anyhow::{Context, anyhow};
use one_core::model::history::{History, HistoryAction, HistoryEntityType};
use one_core::model::organisation::OrganisationRelations;
use one_core::model::trust_entity::{
    TrustEntity, TrustEntityRelations, TrustEntityState, UpdateTrustEntityRequest,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::history_repository::HistoryRepository;
use one_core::repository::trust_entity_repository::TrustEntityRepository;
use one_core::service::trust_entity::dto::{
    GetTrustEntitiesResponseDTO, ListTrustEntitiesQueryDTO,
};
use shared_types::{HistoryId, TrustAnchorId, TrustEntityId, TrustEntityKey};
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

        if let Err(err) = self.create_created_history(entity, trust_entity_id).await {
            tracing::warn!("failed to insert trust entity history event: {err:?}");
        }

        Ok(trust_entity_id)
    }

    async fn get_by_entity_key(
        &self,
        entity_key: &TrustEntityKey,
    ) -> Result<Option<TrustEntity>, DataLayerError> {
        self.inner.get_by_entity_key(entity_key).await
    }

    async fn get_by_entity_key_and_trust_anchor_id(
        &self,
        entity_key: &TrustEntityKey,
        trust_anchor_id: TrustAnchorId,
    ) -> Result<Option<TrustEntity>, DataLayerError> {
        self.inner
            .get_by_entity_key_and_trust_anchor_id(entity_key, trust_anchor_id)
            .await
    }

    async fn get_active_by_trust_anchor_id(
        &self,
        trust_anchor_id: TrustAnchorId,
    ) -> Result<Vec<TrustEntity>, DataLayerError> {
        self.inner
            .get_active_by_trust_anchor_id(trust_anchor_id)
            .await
    }

    async fn delete(&self, id: TrustEntityId) -> Result<(), DataLayerError> {
        let name = self
            .inner
            .get(id, &TrustEntityRelations::default())
            .await?
            .map(|t| t.name)
            .unwrap_or_default();
        self.inner.delete(id).await?;
        if let Err(err) = self.create_history(id, name, HistoryAction::Deleted).await {
            tracing::warn!("failed to insert trust entity history event: {err:?}");
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
        let state_history_action = if let Some(ref state) = request.state {
            match state {
                TrustEntityState::Active => Some(HistoryAction::Activated),
                TrustEntityState::Removed => Some(HistoryAction::Removed),
                TrustEntityState::Withdrawn => Some(HistoryAction::Withdrawn),
                TrustEntityState::RemovedAndWithdrawn => {
                    // Load the entity before updating so that we know which one of removed and withdrawn states is new.
                    let prev_state = self
                        .inner
                        .get(id, &TrustEntityRelations::default())
                        .await?
                        .ok_or(DataLayerError::Db(anyhow!(
                            "trust entity with id {id} not found"
                        )))?
                        .state;
                    match prev_state {
                        TrustEntityState::Removed => Some(HistoryAction::Withdrawn),
                        TrustEntityState::Withdrawn => Some(HistoryAction::Removed),
                        TrustEntityState::RemovedAndWithdrawn => None,
                        // trust entity cannot enter RemovedAndWithdrawn state from Active state
                        TrustEntityState::Active => return Err(DataLayerError::MappingError),
                    }
                }
            }
        } else {
            None
        };

        let content_history_action = request.content.as_ref().map(|_| HistoryAction::Updated);

        for action in [content_history_action, state_history_action]
            .into_iter()
            .flatten()
        {
            let name = self
                .inner
                .get(id, &TrustEntityRelations::default())
                .await?
                .map(|t| t.name)
                .unwrap_or_default();
            if let Err(err) = self.create_history(id, name, action).await {
                tracing::warn!("failed to insert trust entity history event: {err:?}");
            }
        }

        self.inner.update(id, request).await
    }
}

impl TrustEntityHistoryDecorator {
    async fn get_trust_entity_by_id(
        &self,
        id: TrustEntityId,
    ) -> Result<TrustEntity, DataLayerError> {
        let trust_entity = self
            .inner
            .get(
                id,
                &TrustEntityRelations {
                    organisation: Some(OrganisationRelations::default()),
                    ..Default::default()
                },
            )
            .await?
            .context("trust entity is missing")?;

        Ok(trust_entity)
    }

    async fn create_history(
        &self,
        id: TrustEntityId,
        name: String,
        action: HistoryAction,
    ) -> Result<HistoryId, DataLayerError> {
        let trust_entity = self.get_trust_entity_by_id(id).await?;
        self.history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                action,
                name,
                target: None,
                entity_id: Some(id.into()),
                entity_type: HistoryEntityType::TrustEntity,
                metadata: None,
                organisation_id: trust_entity.organisation.map(|o| o.id),
            })
            .await
    }

    async fn create_created_history(
        &self,
        entity: TrustEntity,
        trust_entity_id: TrustEntityId,
    ) -> Result<HistoryId, DataLayerError> {
        self.history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: entity.created_date,
                action: HistoryAction::Created,
                name: entity.name.clone(),
                target: None,
                entity_id: Some(trust_entity_id.into()),
                entity_type: HistoryEntityType::TrustEntity,
                metadata: None,
                organisation_id: entity.organisation.map(|o| o.id),
            })
            .await
    }
}
