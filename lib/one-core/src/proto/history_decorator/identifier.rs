use std::sync::Arc;

use shared_types::{DidId, IdentifierId, OrganisationId};
use uuid::Uuid;

use crate::model::history::{History, HistoryAction, HistoryEntityType, HistorySource};
use crate::model::identifier::{
    GetIdentifierList, Identifier, IdentifierListQuery, IdentifierState, UpdateIdentifierRequest,
};
use crate::proto::session_provider::{SessionExt, SessionProvider};
use crate::repository::error::DataLayerError;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::identifier_repository::IdentifierRepository;

pub struct IdentifierHistoryDecorator {
    pub history_repository: Arc<dyn HistoryRepository>,
    pub inner: Arc<dyn IdentifierRepository>,
    pub session_provider: Arc<dyn SessionProvider>,
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
                created_date: crate::clock::now_utc(),
                action,
                name,
                source: HistorySource::Core,
                target: None,
                entity_id: Some(id.into()),
                entity_type: HistoryEntityType::Identifier,
                metadata: None,
                metadata_blob_id: None,
                organisation_id: Some(organisation_id),
                user: self.session_provider.session().user(),
            })
            .await;

        if let Err(error) = result {
            tracing::warn!(%error, "failed to insert identifier history event");
        }
    }
}

#[async_trait::async_trait]
impl IdentifierRepository for IdentifierHistoryDecorator {
    async fn get(&self, id: IdentifierId) -> Result<Identifier, DataLayerError> {
        self.inner.get(id).await
    }
    async fn get_from_did_id(&self, did_id: DidId) -> Result<Option<Identifier>, DataLayerError> {
        self.inner.get_from_did_id(did_id).await
    }
    async fn get_identifier_list(
        &self,
        query_params: IdentifierListQuery,
    ) -> Result<GetIdentifierList, DataLayerError> {
        self.inner.get_identifier_list(query_params).await
    }

    async fn get_identifiers_by_ids(
        &self,
        ids: Vec<IdentifierId>,
    ) -> Result<Vec<Identifier>, DataLayerError> {
        self.inner.get_identifiers_by_ids(ids).await
    }

    async fn create(&self, request: Identifier) -> Result<IdentifierId, DataLayerError> {
        let name = request.name.clone();
        let organisation_id = request.organisation.id();
        let identifier_id = self.inner.create(request).await?;

        self.create_history(identifier_id, name, HistoryAction::Created, organisation_id)
            .await;

        Ok(identifier_id)
    }

    async fn update(
        &self,
        id: &IdentifierId,
        request: UpdateIdentifierRequest,
    ) -> Result<(), DataLayerError> {
        self.inner.update(id, request.clone()).await?;

        if let Some(state) = request.state {
            let identifier = self.inner.get(*id).await?;

            self.create_history(
                identifier.id,
                identifier.name,
                if state == IdentifierState::Deactivated {
                    HistoryAction::Deactivated
                } else {
                    HistoryAction::Reactivated
                },
                identifier.organisation.id(),
            )
            .await;
        }

        Ok(())
    }

    async fn delete(&self, id: &IdentifierId) -> Result<(), DataLayerError> {
        let identifier = self.inner.get(*id).await;

        self.inner.delete(id).await?;

        let identifier = identifier?;

        self.create_history(
            identifier.id,
            identifier.name,
            HistoryAction::Deleted,
            identifier.organisation.id(),
        )
        .await;

        Ok(())
    }

    async fn hard_delete(&self, id: &IdentifierId) -> Result<(), DataLayerError> {
        self.inner.hard_delete(id).await
    }
}
