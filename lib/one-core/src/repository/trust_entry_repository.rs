use shared_types::{TrustEntryId, TrustListPublicationId};

use crate::model::trust_entry::{
    GetTrustEntryList, TrustEntry, TrustEntryListQuery, TrustEntryRelations,
    UpdateTrustEntryRequest,
};
use crate::repository::error::DataLayerError;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait TrustEntryRepository: Send + Sync {
    async fn create(&self, entity: TrustEntry) -> Result<TrustEntryId, DataLayerError>;

    async fn get(
        &self,
        id: TrustEntryId,
        relations: &TrustEntryRelations,
    ) -> Result<Option<TrustEntry>, DataLayerError>;

    async fn list(
        &self,
        trust_list_publication_id: TrustListPublicationId,
        query: TrustEntryListQuery,
    ) -> Result<GetTrustEntryList, DataLayerError>;

    async fn update(
        &self,
        id: TrustEntryId,
        request: UpdateTrustEntryRequest,
    ) -> Result<(), DataLayerError>;

    async fn delete(&self, id: TrustEntryId) -> Result<(), DataLayerError>;
}
