pub mod error;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use one_dto_mapper::From;
use shared_types::BlobId;
use strum::Display;

use crate::config::core_config;
use crate::config::core_config::{BlobStorageConfig, ConfigFields};
use crate::model::blob::{Blob, UpdateBlobRequest};
use crate::provider::blob_storage_provider::error::BlobStorageError;
use crate::repository::blob_repository::BlobRepository;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub trait BlobStorageProvider: Send + Sync {
    async fn get_blob_storage(&self, r#type: BlobStorageType) -> Option<Arc<dyn BlobStorage>>;
}

#[derive(Clone, Debug, Copy, Display, PartialEq, Eq, PartialOrd, Ord, Hash, From)]
#[from(crate::config::core_config::BlobStorageType)]
pub enum BlobStorageType {
    Db,
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub trait BlobStorage: Send + Sync {
    async fn create(&self, blob: Blob) -> Result<(), BlobStorageError>;

    async fn get(&self, id: &BlobId) -> Result<Option<Blob>, BlobStorageError>;

    async fn update(&self, id: &BlobId, update: UpdateBlobRequest) -> Result<(), BlobStorageError>;

    async fn delete(&self, id: &BlobId) -> Result<(), BlobStorageError>;

    async fn delete_many(&self, ids: &[BlobId]) -> Result<(), BlobStorageError>;
}

struct BlobStorageProviderImpl {
    storages: HashMap<BlobStorageType, Arc<dyn BlobStorage>>,
}

impl BlobStorageProviderImpl {
    fn new(storages: HashMap<BlobStorageType, Arc<dyn BlobStorage>>) -> Self {
        Self { storages }
    }
}

#[async_trait]
impl BlobStorageProvider for BlobStorageProviderImpl {
    async fn get_blob_storage(&self, r#type: BlobStorageType) -> Option<Arc<dyn BlobStorage>> {
        self.storages.get(&r#type).map(Arc::clone)
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

    async fn delete_many(&self, ids: &[BlobId]) -> Result<(), BlobStorageError> {
        self.blob_repository
            .delete_many(ids)
            .await
            .map_err(Into::into)
    }
}

pub(crate) fn blob_storage_provider_from_config(
    blob_storage_config: &BlobStorageConfig,
    blob_repository: Arc<dyn BlobRepository>,
) -> Arc<dyn BlobStorageProvider> {
    let mut providers: HashMap<BlobStorageType, Arc<dyn BlobStorage>> = HashMap::new();

    for (r#type, fields) in blob_storage_config.iter() {
        if !fields.enabled() {
            continue;
        }
        let blob_provider = match r#type {
            core_config::BlobStorageType::Db => RepositoryBlobStorage {
                blob_repository: blob_repository.clone(),
            },
        };
        providers.insert((*r#type).into(), Arc::new(blob_provider));
    }

    Arc::new(BlobStorageProviderImpl::new(providers))
}
