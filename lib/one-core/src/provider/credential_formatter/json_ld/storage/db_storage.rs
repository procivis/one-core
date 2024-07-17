use crate::model;
use crate::repository::json_ld_context_repository::JsonLdContextRepository;
use async_trait::async_trait;
use one_providers::credential_formatter::imp::json_ld::context::storage;
use one_providers::credential_formatter::imp::json_ld::context::storage::{
    JsonLdContextStorage, JsonLdContextStorageError,
};
use shared_types::JsonLdContextId;
use std::sync::Arc;
use uuid::Uuid;

pub struct DbStorage {
    json_ld_context_repository: Arc<dyn JsonLdContextRepository>,
}

impl DbStorage {
    pub fn new(json_ld_context_repository: Arc<dyn JsonLdContextRepository>) -> Self {
        Self {
            json_ld_context_repository,
        }
    }
}

#[async_trait]
impl JsonLdContextStorage for DbStorage {
    async fn delete_oldest_context(&self) -> Result<(), JsonLdContextStorageError> {
        self.json_ld_context_repository
            .delete_oldest_context()
            .await
            .map_err(|e| JsonLdContextStorageError::DeleteError(e.to_string()))
    }

    async fn get_json_ld_context_by_url(
        &self,
        url: &str,
    ) -> Result<Option<storage::JsonLdContext>, JsonLdContextStorageError> {
        Ok(self
            .json_ld_context_repository
            .get_json_ld_context_by_url(url)
            .await
            .map_err(|e| JsonLdContextStorageError::GetByUrlError(e.to_string()))?
            .map(db_context_to_storage_context))
    }

    async fn get_storage_size(&self) -> Result<usize, JsonLdContextStorageError> {
        Ok(self
            .json_ld_context_repository
            .get_repository_size()
            .await
            .map_err(|e| JsonLdContextStorageError::GetStorageSizeError(e.to_string()))?
            as usize)
    }

    async fn insert_json_ld_context(
        &self,
        request: storage::JsonLdContext,
    ) -> Result<(), JsonLdContextStorageError> {
        if let Some(db_context) = self
            .json_ld_context_repository
            .get_json_ld_context_by_url(request.url.as_str())
            .await
            .map_err(|e| JsonLdContextStorageError::InsertError(e.to_string()))?
        {
            self.json_ld_context_repository
                .update_json_ld_context(storage_context_to_db_context(db_context.id, request))
                .await
                .map_err(|e| JsonLdContextStorageError::InsertError(e.to_string()))?;
        } else {
            self.json_ld_context_repository
                .create_json_ld_context(storage_context_to_db_context(
                    Uuid::new_v4().into(),
                    request,
                ))
                .await
                .map_err(|e| JsonLdContextStorageError::InsertError(e.to_string()))?;
        }

        Ok(())
    }
}

fn db_context_to_storage_context(
    db_context: model::json_ld_context::JsonLdContext,
) -> storage::JsonLdContext {
    storage::JsonLdContext {
        last_modified: db_context.last_modified,
        context: db_context.context,
        url: db_context.url,
        hit_counter: db_context.hit_counter,
    }
}

fn storage_context_to_db_context(
    id: JsonLdContextId,
    storage_context: storage::JsonLdContext,
) -> model::json_ld_context::JsonLdContext {
    model::json_ld_context::JsonLdContext {
        id,
        created_date: storage_context.last_modified,
        last_modified: storage_context.last_modified,
        context: storage_context.context,
        url: storage_context.url,
        hit_counter: storage_context.hit_counter,
    }
}
