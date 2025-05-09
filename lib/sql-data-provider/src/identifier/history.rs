use std::sync::Arc;

use anyhow::Context;
use one_core::model::history::{History, HistoryAction, HistoryEntityType};
use one_core::model::identifier::{
    GetIdentifierList, Identifier, IdentifierListQuery, IdentifierRelations,
    UpdateIdentifierRequest,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::history_repository::HistoryRepository;
use one_core::repository::identifier_repository::IdentifierRepository;
use shared_types::{DidId, IdentifierId, OrganisationId};
use time::OffsetDateTime;
use uuid::Uuid;

pub struct IdentifierHistoryDecorator {
    pub history_repository: Arc<dyn HistoryRepository>,
    pub inner: Arc<dyn IdentifierRepository>,
}

impl IdentifierHistoryDecorator {
    async fn create_history(
        &self,
        id: IdentifierId,
        name: String,
        action: HistoryAction,
        organisation_id: OrganisationId,
    ) {
        let result = self
            .history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                action,
                name,
                target: None,
                entity_id: Some(id.into()),
                entity_type: HistoryEntityType::Identifier,
                metadata: None,
                organisation_id,
            })
            .await;

        if let Err(error) = result {
            tracing::warn!(%error, "failed to insert identifier history event");
        }
    }
}

#[async_trait::async_trait]
impl IdentifierRepository for IdentifierHistoryDecorator {
    async fn get(
        &self,
        id: IdentifierId,
        relations: &IdentifierRelations,
    ) -> Result<Option<Identifier>, DataLayerError> {
        self.inner.get(id, relations).await
    }
    async fn get_from_did_id(
        &self,
        did_id: DidId,
        relations: &IdentifierRelations,
    ) -> Result<Option<Identifier>, DataLayerError> {
        self.inner.get_from_did_id(did_id, relations).await
    }
    async fn get_identifier_list(
        &self,
        query_params: IdentifierListQuery,
    ) -> Result<GetIdentifierList, DataLayerError> {
        self.inner.get_identifier_list(query_params).await
    }

    async fn create(&self, request: Identifier) -> Result<IdentifierId, DataLayerError> {
        let id = request.id;
        let name = request.name.clone();
        let organisation_id = request.organisation.as_ref().map(|o| o.id);
        let identifier_id = self.inner.create(request).await?;

        if let Some(organisation_id) = organisation_id {
            self.create_history(id, name, HistoryAction::Created, organisation_id)
                .await;
        } else {
            tracing::warn!("identifier (id: {identifier_id}) missing organisation");
        }

        Ok(identifier_id)
    }

    async fn update(
        &self,
        id: &IdentifierId,
        request: UpdateIdentifierRequest,
    ) -> Result<(), DataLayerError> {
        self.inner.update(id, request.clone()).await?;

        if request.status.is_none() {
            return Ok(());
        };

        let identifier = self
            .inner
            .get(
                *id,
                &IdentifierRelations {
                    organisation: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await?
            .context("identifier is missing")?;

        if let Some(organisation) = identifier.organisation {
            self.create_history(
                identifier.id,
                identifier.name,
                HistoryAction::Deactivated,
                organisation.id,
            )
            .await;
        } else {
            tracing::warn!("identifier (id: {id}) missing organisation");
        }

        Ok(())
    }

    async fn delete(&self, id: &IdentifierId) -> Result<(), DataLayerError> {
        let identifier = self
            .inner
            .get(
                *id,
                &IdentifierRelations {
                    organisation: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await;

        self.inner.delete(id).await?;

        let identifier = identifier?.context("identifier is missing")?;

        if let Some(organisation) = identifier.organisation {
            self.create_history(
                identifier.id,
                identifier.name,
                HistoryAction::Deleted,
                organisation.id,
            )
            .await;
        } else {
            tracing::warn!("identifier (id: {id}) missing organisation");
        }

        Ok(())
    }
}
