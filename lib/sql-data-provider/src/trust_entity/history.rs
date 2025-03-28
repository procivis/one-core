use std::sync::Arc;

use anyhow::Context;
use one_core::model::did::DidRelations;
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
use shared_types::{DidId, HistoryId, TrustAnchorId, TrustEntityId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::trust_entity::mapper::trust_entity_to_organisation_id;

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

    async fn get_by_did_id(&self, did_id: DidId) -> Result<Option<TrustEntity>, DataLayerError> {
        self.inner.get_by_did_id(did_id).await
    }

    async fn get_by_did_id_and_trust_anchor_id(
        &self,
        did_id: DidId,
        trust_anchor_id: TrustAnchorId,
    ) -> Result<Option<TrustEntity>, DataLayerError> {
        self.inner
            .get_by_did_id_and_trust_anchor_id(did_id, trust_anchor_id)
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
        if let Err(err) = self.create_history(id, name, HistoryAction::Created).await {
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
        let history_action = request.state.clone().and_then(|state| match state {
            TrustEntityState::Active => Some(HistoryAction::Activated),
            TrustEntityState::Removed => Some(HistoryAction::Removed),
            TrustEntityState::Withdrawn => Some(HistoryAction::Withdrawn),
            TrustEntityState::RemovedAndWithdrawn => None,
        });

        if let Some(action) = history_action {
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
                    did: Some(DidRelations {
                        organisation: Some(OrganisationRelations::default()),
                        ..Default::default()
                    }),
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
                entity_id: Some(id.into()),
                entity_type: HistoryEntityType::TrustEntity,
                metadata: None,
                organisation_id: trust_entity_to_organisation_id(trust_entity)?,
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
                entity_id: Some(trust_entity_id.into()),
                entity_type: HistoryEntityType::TrustEntity,
                metadata: None,
                organisation_id: trust_entity_to_organisation_id(entity)?,
            })
            .await
    }
}
