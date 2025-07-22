use async_trait::async_trait;
use shared_types::BlobId;

use crate::model::blob::{Blob, UpdateBlobRequest};
use crate::repository::error::DataLayerError;

#[async_trait]
pub trait BlobRepository: Send + Sync {
    async fn create(&self, blob: Blob) -> Result<(), DataLayerError>;

    async fn get(&self, id: &BlobId) -> Result<Option<Blob>, DataLayerError>;

    async fn update(&self, id: &BlobId, update: UpdateBlobRequest) -> Result<(), DataLayerError>;

    async fn delete(&self, id: &BlobId) -> Result<(), DataLayerError>;
}
