use std::sync::Arc;

use anyhow::Context;
use shared_types::{TrustAnchorId, TrustEntityId, TrustEntityKey};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::history::{History, HistoryAction, HistoryEntityType, HistorySource};
use crate::model::organisation::{Organisation, OrganisationRelations};
use crate::model::trust_entity::{
    TrustEntity, TrustEntityRelations, TrustEntityState, UpdateTrustEntityRequest,
};
use crate::proto::session_provider::{SessionExt, SessionProvider};
use crate::repository::error::DataLayerError;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::trust_entity_repository::TrustEntityRepository;
use crate::service::trust_entity::dto::{GetTrustEntitiesResponseDTO, ListTrustEntitiesQueryDTO};

pub struct TrustEntityHistoryDecorator {
    pub history_repository: Arc<dyn HistoryRepository>,
    pub inner: Arc<dyn TrustEntityRepository>,
    pub session_provider: Arc<dyn SessionProvider>,
}

#[async_trait::async_trait]
impl TrustEntityRepository for TrustEntityHistoryDecorator {
    async fn create(&self, entity: TrustEntity) -> Result<TrustEntityId, DataLayerError> {
        let trust_entity_id = self.inner.create(entity.clone()).await?;

        self.write_history(
            trust_entity_id,
            entity.name,
            HistoryAction::Created,
            entity.organisation.as_ref(),
        )
        .await;

        Ok(trust_entity_id)
    }

    async fn update(
        &self,
        id: TrustEntityId,
        request: UpdateTrustEntityRequest,
    ) -> Result<(), DataLayerError> {
        let old_entity = self.get_trust_entity_by_id(id).await?;
        let state_history_action = if let Some(ref new_state) = request.state {
            match new_state {
                TrustEntityState::Active => Some(HistoryAction::Activated),
                TrustEntityState::Removed => Some(HistoryAction::Removed),
                TrustEntityState::Withdrawn => Some(HistoryAction::Withdrawn),
                TrustEntityState::RemovedAndWithdrawn => {
                    match old_entity.state {
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

        let updated = request.content.is_some()
            || request.name.is_some()
            || request.logo.is_some()
            || request.privacy_url.is_some()
            || request.terms_url.is_some()
            || request.website.is_some()
            || request.role.is_some();

        self.inner.update(id, request).await?;

        if updated {
            self.write_history(
                id,
                old_entity.name.to_owned(),
                HistoryAction::Updated,
                old_entity.organisation.as_ref(),
            )
            .await;
        }

        if let Some(state_history_action) = state_history_action {
            self.write_history(
                id,
                old_entity.name,
                state_history_action,
                old_entity.organisation.as_ref(),
            )
            .await;
        }

        Ok(())
    }

    async fn delete(&self, id: TrustEntityId) -> Result<(), DataLayerError> {
        let entity = self.get_trust_entity_by_id(id).await?;
        self.inner.delete(id).await?;
        self.write_history(
            id,
            entity.name,
            HistoryAction::Deleted,
            entity.organisation.as_ref(),
        )
        .await;
        Ok(())
    }

    async fn get_by_entity_key(
        &self,
        entity_key: &TrustEntityKey,
    ) -> Result<Option<TrustEntity>, DataLayerError> {
        self.inner.get_by_entity_key(entity_key).await
    }

    async fn get_active_by_trust_anchor_id(
        &self,
        trust_anchor_id: TrustAnchorId,
    ) -> Result<Vec<TrustEntity>, DataLayerError> {
        self.inner
            .get_active_by_trust_anchor_id(trust_anchor_id)
            .await
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

    async fn write_history(
        &self,
        id: TrustEntityId,
        name: String,
        action: HistoryAction,
        organisation: Option<&Organisation>,
    ) {
        let result = self
            .history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                action,
                name,
                source: HistorySource::Core,
                target: None,
                entity_id: Some(id.into()),
                entity_type: HistoryEntityType::TrustEntity,
                metadata: None,
                organisation_id: organisation.map(|o| o.id),
                user: self.session_provider.session().user(),
            })
            .await;

        if let Err(err) = result {
            tracing::warn!("failed to insert trust entity history event: {err:?}");
        }
    }
}
