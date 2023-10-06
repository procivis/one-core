use super::error::DataLayerError;
use crate::model::key::{Key, KeyId, KeyRelations};

#[async_trait::async_trait]
pub trait KeyRepository {
    async fn create_key(&self, request: Key) -> Result<KeyId, DataLayerError>;
    async fn get_key(&self, id: &KeyId, relations: &KeyRelations) -> Result<Key, DataLayerError>;
}
