use shared_types::{IdentifierId, RevocationListEntryId, RevocationListId};

use super::error::DataLayerError;
use crate::model::common::LockType;
use crate::model::revocation_list::{
    RevocationList, RevocationListEntityId, RevocationListEntry, RevocationListPurpose,
    RevocationListRelations, StatusListType, UpdateRevocationListEntryId,
    UpdateRevocationListEntryRequest,
};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait RevocationListRepository: Send + Sync {
    async fn create_revocation_list(
        &self,
        request: RevocationList,
    ) -> Result<RevocationListId, DataLayerError>;

    async fn get_revocation_list(
        &self,
        id: &RevocationListId,
        relations: &RevocationListRelations,
    ) -> Result<Option<RevocationList>, DataLayerError>;

    async fn get_revocation_list_by_entry_id(
        &self,
        entry_id: RevocationListEntryId,
        relations: &RevocationListRelations,
    ) -> Result<Option<RevocationList>, DataLayerError>;

    async fn get_revocation_by_issuer_identifier_id(
        &self,
        issuer_identifier_id: IdentifierId,
        purpose: RevocationListPurpose,
        status_list_type: StatusListType,
        relations: &RevocationListRelations,
    ) -> Result<Option<RevocationList>, DataLayerError>;

    async fn update_credentials(
        &self,
        revocation_list_id: &RevocationListId,
        credentials: Vec<u8>,
    ) -> Result<(), DataLayerError>;

    async fn next_free_index(
        &self,
        id: &RevocationListId,
        lock: Option<LockType>,
    ) -> Result<usize, DataLayerError>;

    async fn create_entry(
        &self,
        list_id: RevocationListId,
        entity_id: RevocationListEntityId,
        index_on_status_list: usize,
    ) -> Result<RevocationListEntryId, DataLayerError>;

    async fn update_entry(
        &self,
        id: UpdateRevocationListEntryId,
        request: UpdateRevocationListEntryRequest,
    ) -> Result<(), DataLayerError>;

    async fn get_entry_by_id(
        &self,
        id: RevocationListEntryId,
    ) -> Result<Option<RevocationListEntry>, DataLayerError>;

    async fn get_entries(
        &self,
        list_id: RevocationListId,
    ) -> Result<Vec<RevocationListEntry>, DataLayerError>;

    async fn get_entries_by_id(
        &self,
        entry_ids: Vec<RevocationListEntryId>,
    ) -> Result<Vec<RevocationListEntry>, DataLayerError>;
}
