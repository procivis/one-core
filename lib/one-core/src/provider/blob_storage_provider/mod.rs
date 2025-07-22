pub mod error;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use shared_types::BlobId;

use crate::config::ConfigError;
use crate::config::core_config::{BlobStorageConfig, BlobStorageType};
use crate::model::blob::{Blob, UpdateBlobRequest};
use crate::provider::blob_storage_provider::error::BlobStorageError;
use crate::repository::blob_repository::BlobRepository;

// #[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub trait BlobStorageProvider: Send + Sync {
    async fn get_blob_storage(
        &self,
        r#type: impl AsRef<str> + Send + Sync,
    ) -> Option<Arc<dyn BlobStorage>>;
}

// #[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub trait BlobStorage: Send + Sync {
    async fn create(&self, blob: Blob) -> Result<(), BlobStorageError>;

    async fn get(&self, id: &BlobId) -> Result<Option<Blob>, BlobStorageError>;

    async fn update(&self, id: &BlobId, update: UpdateBlobRequest) -> Result<(), BlobStorageError>;

    async fn delete(&self, id: &BlobId) -> Result<(), BlobStorageError>;
}

pub struct BlobStorageProviderImpl {
    storages: HashMap<String, Arc<dyn BlobStorage>>,
}

impl BlobStorageProviderImpl {
    pub fn new(storages: HashMap<String, Arc<dyn BlobStorage>>) -> Self {
        Self { storages }
    }
}

#[async_trait]
impl BlobStorageProvider for BlobStorageProviderImpl {
    async fn get_blob_storage(
        &self,
        r#type: impl AsRef<str> + Send + Sync,
    ) -> Option<Arc<dyn BlobStorage>> {
        self.storages.get(r#type.as_ref()).map(Arc::clone)
    }
}

pub struct RepositoryBlobStorage {
    blob_repository: Arc<dyn BlobRepository>,
}

#[async_trait]
impl BlobStorage for RepositoryBlobStorage {
    async fn create(&self, blob: Blob) -> Result<(), BlobStorageError> {
        self.blob_repository.create(blob).await.map_err(Into::into)
    }

    async fn get(&self, id: &BlobId) -> Result<Option<Blob>, BlobStorageError> {
        self.blob_repository.get(id).await.map_err(Into::into)
    }

    async fn update(&self, id: &BlobId, update: UpdateBlobRequest) -> Result<(), BlobStorageError> {
        self.blob_repository
            .update(id, update)
            .await
            .map_err(Into::into)
    }

    async fn delete(&self, id: &BlobId) -> Result<(), BlobStorageError> {
        self.blob_repository.delete(id).await.map_err(Into::into)
    }
}

pub(crate) fn blob_storage_providers_from_config(
    blob_storage_config: &BlobStorageConfig,
    blob_repository: Arc<dyn BlobRepository>,
) -> Result<HashMap<String, Arc<dyn BlobStorage>>, ConfigError> {
    let mut providers: HashMap<String, Arc<dyn BlobStorage>> = HashMap::new();

    for (name, fields) in blob_storage_config.iter() {
        if !fields.enabled() {
            continue;
        }
        let blob_provider = match fields.r#type {
            BlobStorageType::Db => RepositoryBlobStorage {
                blob_repository: blob_repository.clone(),
            },
        };
        providers.insert(name.to_string(), Arc::new(blob_provider));
    }

    Ok(providers)
}
