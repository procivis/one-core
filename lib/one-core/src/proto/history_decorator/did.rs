use std::sync::Arc;

use shared_types::{DidId, DidValue, OrganisationId};
use uuid::Uuid;

use crate::model::did::{Did, DidListQuery, GetDidList, RelatedKey, UpdateDidRequest};
use crate::model::history::{History, HistoryAction, HistoryEntityType, HistorySource};
use crate::proto::session_provider::{SessionExt, SessionProvider};
use crate::repository::did_repository::DidRepository;
use crate::repository::error::DataLayerError;
use crate::repository::history_repository::HistoryRepository;

pub struct DidHistoryDecorator {
    pub history_repository: Arc<dyn HistoryRepository>,
    pub inner: Arc<dyn DidRepository>,
    pub session_provider: Arc<dyn SessionProvider>,
}

impl DidHistoryDecorator {
    async fn create_history(
        &self,
        id: DidId,
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
                entity_type: HistoryEntityType::Did,
                metadata: None,
                metadata_blob_id: None,
                organisation_id: Some(organisation_id),
                user: self.session_provider.session().user(),
            })
            .await;

        if let Err(error) = result {
            tracing::warn!(%error, "failed to insert did history event");
        }
    }
}

#[async_trait::async_trait]
impl DidRepository for DidHistoryDecorator {
    async fn create_did(&self, request: Did) -> Result<DidId, DataLayerError> {
        let name = request.name.clone();
        let organisation_id = request.organisation.id();
        let did_id = self.inner.create_did(request).await?;

        self.create_history(did_id, name, HistoryAction::Created, organisation_id)
            .await;

        Ok(did_id)
    }

    async fn get_did(&self, id: &DidId) -> Result<Did, DataLayerError> {
        self.inner.get_did(id).await
    }

    async fn get_did_by_value(
        &self,
        value: &DidValue,
        organisation: Option<Option<OrganisationId>>,
    ) -> Result<Option<Did>, DataLayerError> {
        self.inner.get_did_by_value(value, organisation).await
    }

    async fn get_did_list(&self, query: DidListQuery) -> Result<GetDidList, DataLayerError> {
        self.inner.get_did_list(query).await
    }

    async fn update_did(
        &self,
        id: &DidId,
        request: UpdateDidRequest,
    ) -> Result<(), DataLayerError> {
        self.inner.update_did(id, request.clone()).await?;

        if let Some(deactivated) = request.deactivated {
            let did = self.inner.get_did(id).await?;

            self.create_history(
                did.id,
                did.name,
                if deactivated {
                    HistoryAction::Deactivated
                } else {
                    HistoryAction::Reactivated
                },
                did.organisation.id(),
            )
            .await;
        };

        Ok(())
    }

    async fn update_did_keys(
        &self,
        id: &DidId,
        keys: Vec<RelatedKey>,
    ) -> Result<(), DataLayerError> {
        self.inner.update_did_keys(id, keys).await?;
        let did = self.inner.get_did(id).await?;
        self.create_history(
            did.id,
            did.name,
            HistoryAction::Updated,
            did.organisation.id(),
        )
        .await;
        Ok(())
    }

    async fn delete_did(&self, did: &Did) -> Result<(), DataLayerError> {
        self.inner.delete_did(did).await?;
        self.create_history(
            did.id,
            did.name.clone(),
            HistoryAction::Deleted,
            did.organisation.id(),
        )
        .await;
        Ok(())
    }

    async fn hard_delete(&self, id: &DidId) -> Result<(), DataLayerError> {
        self.inner.hard_delete(id).await
    }
}
