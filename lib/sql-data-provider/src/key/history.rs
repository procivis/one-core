use std::sync::Arc;

use one_core::model::history::{History, HistoryAction, HistoryEntityType};
use one_core::model::key::{GetKeyList, Key, KeyListQuery, KeyRelations};
use one_core::repository::error::DataLayerError;
use one_core::repository::history_repository::HistoryRepository;
use one_core::repository::key_repository::KeyRepository;
use shared_types::KeyId;
use uuid::Uuid;

pub struct KeyHistoryDecorator {
    pub history_repository: Arc<dyn HistoryRepository>,
    pub inner: Arc<dyn KeyRepository>,
}

#[async_trait::async_trait]
impl KeyRepository for KeyHistoryDecorator {
    async fn create_key(&self, request: Key) -> Result<KeyId, DataLayerError> {
        let key_id = self.inner.create_key(request.clone()).await?;

        let result = self
            .history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: request.created_date,
                action: HistoryAction::Created,
                entity_id: Some(key_id.into()),
                entity_type: HistoryEntityType::Key,
                metadata: None,
                organisation: request.organisation,
            })
            .await;

        if let Err(err) = result {
            tracing::debug!("failed to insert key history event: {err:?}");
        }

        Ok(key_id)
    }

    async fn get_key(
        &self,
        id: &KeyId,
        relations: &KeyRelations,
    ) -> Result<Option<Key>, DataLayerError> {
        self.inner.get_key(id, relations).await
    }

    async fn get_keys(&self, ids: &[KeyId]) -> Result<Vec<Key>, DataLayerError> {
        self.inner.get_keys(ids).await
    }

    async fn get_key_list(&self, query_params: KeyListQuery) -> Result<GetKeyList, DataLayerError> {
        self.inner.get_key_list(query_params).await
    }
}
