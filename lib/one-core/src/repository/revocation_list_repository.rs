use shared_types::IdentifierId;

use super::error::DataLayerError;
use crate::model::revocation_list::{
    RevocationList, RevocationListEntityId, RevocationListEntry, RevocationListId,
    RevocationListPurpose, RevocationListRelations, StatusListType,
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

    async fn get_max_used_index(
        &self,
        id: &RevocationListId,
    ) -> Result<Option<usize>, DataLayerError>;

    async fn create_entry(
        &self,
        list_id: RevocationListId,
        entity_id: RevocationListEntityId,
        index_on_status_list: usize,
    ) -> Result<(), DataLayerError>;

    async fn get_entries(
        &self,
        list_id: RevocationListId,
    ) -> Result<Vec<RevocationListEntry>, DataLayerError>;
}
