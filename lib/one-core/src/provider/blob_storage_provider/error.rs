use thiserror::Error;

use crate::repository::error::DataLayerError;

#[derive(Debug, Error)]
pub enum BlobStorageError {
    #[error("Blob storage data layer error: `{0}`")]
    DataLayerError(#[from] DataLayerError),
}
