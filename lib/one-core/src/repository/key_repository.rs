use super::error::DataLayerError;
use crate::model::key::{Key, KeyId};

#[async_trait::async_trait]
pub trait KeyRepository {
    async fn create_key(&self, request: Key) -> Result<KeyId, DataLayerError>;
}
