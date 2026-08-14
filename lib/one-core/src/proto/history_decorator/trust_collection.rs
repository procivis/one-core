use std::sync::Arc;

use shared_types::{OrganisationId, TrustCollectionId};
use uuid::Uuid;

use crate::model::history::{History, HistoryAction, HistoryEntityType, HistorySource};
use crate::model::trust_collection::{
    GetTrustCollectionList, TrustCollection, TrustCollectionListQuery,
};
use crate::proto::session_provider::{SessionExt, SessionProvider};
use crate::repository::error::DataLayerError;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::trust_collection_repository::TrustCollectionRepository;

pub struct TrustCollectionHistoryDecorator {
    pub history_repository: Arc<dyn HistoryRepository>,
    pub inner: Arc<dyn TrustCollectionRepository>,
    pub session_provider: Arc<dyn SessionProvider>,
}

#[async_trait::async_trait]
impl TrustCollectionRepository for TrustCollectionHistoryDecorator {
    async fn create(&self, entity: TrustCollection) -> Result<TrustCollectionId, DataLayerError> {
        let trust_list_publication_id = self.inner.create(entity.clone()).await?;

        self.write_history(
            trust_list_publication_id,
            entity.name,
            HistoryAction::Created,
            entity.organisation.id(),
        )
        .await;

        Ok(trust_list_publication_id)
    }

    async fn get(&self, id: &TrustCollectionId) -> Result<TrustCollection, DataLayerError> {
        self.inner.get(id).await
    }

    async fn list(
        &self,
        query: TrustCollectionListQuery,
    ) -> Result<GetTrustCollectionList, DataLayerError> {
        self.inner.list(query).await
    }

    async fn delete(&self, id: TrustCollectionId) -> Result<(), DataLayerError> {
        let trust_collection = self.inner.get(&id).await;
        self.inner.delete(id).await?;

        let trust_collection = trust_collection?;
        self.write_history(
            id,
            trust_collection.name,
            HistoryAction::Deleted,
            trust_collection.organisation.id(),
        )
        .await;
        Ok(())
    }
}

impl TrustCollectionHistoryDecorator {
    async fn write_history(
        &self,
        id: TrustCollectionId,
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
                entity_type: HistoryEntityType::TrustCollection,
                metadata: None,
                metadata_blob_id: None,
                organisation_id: Some(organisation_id),
                user: self.session_provider.session().user(),
            })
            .await;

        if let Err(err) = result {
            tracing::warn!("failed to insert trust collection history event: {err:?}");
        }
    }
}
