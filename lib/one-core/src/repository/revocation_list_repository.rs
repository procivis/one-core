use shared_types::{CredentialId, IdentifierId};

use super::error::DataLayerError;
use crate::model::revocation_list::{
    RevocationList, RevocationListCredentialEntry, RevocationListId, RevocationListPurpose,
    RevocationListRelations, StatusListType,
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

    async fn get_revocation_lists(
        &self,
        ids: &[RevocationListId],
        relations: &RevocationListRelations,
    ) -> Result<Vec<RevocationList>, DataLayerError>;

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

    async fn create_credential_entry(
        &self,
        list_id: RevocationListId,
        credential_id: CredentialId,
        index_on_status_list: usize,
    ) -> Result<(), DataLayerError>;

    async fn get_linked_credentials(
        &self,
        list_id: RevocationListId,
    ) -> Result<Vec<RevocationListCredentialEntry>, DataLayerError>;
}
