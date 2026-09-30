use crate::model::localized_text::LocalizedText;
use crate::repository::error::DataLayerError;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait LocalizedTextRepository: Send + Sync {
    async fn upsert(&self, localized_text: LocalizedText) -> Result<(), DataLayerError>;

    /// Upserts translations by entity ID, language and field. For duplicate keys, the last value wins.
    async fn upsert_many(&self, localized_texts: Vec<LocalizedText>) -> Result<(), DataLayerError>;
    async fn get(&self, id: &shared_types::EntityId) -> Result<Vec<LocalizedText>, DataLayerError>;
}
