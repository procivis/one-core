use std::sync::Arc;

use shared_types::{
    CertificateId, CredentialId, IdentifierId, RevocationListEntryId, RevocationListId,
    RevocationMethodId,
};

use super::error::DataLayerError;
use crate::model::common::LockType;
use crate::model::relation::AsyncModelLoader;
use crate::model::revocation_list::{
    RevocationList, RevocationListEntityId, RevocationListEntryList, RevocationListEntryListQuery,
    RevocationListPurpose, UpdateRevocationListEntryId, UpdateRevocationListEntryRequest,
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
    ) -> Result<RevocationList, DataLayerError>;

    async fn get_revocation_list_by_entry_id(
        &self,
        entry_id: RevocationListEntryId,
    ) -> Result<RevocationList, DataLayerError>;

    async fn get_latest_list_by_issuer(
        &self,
        issuer_identifier_id: IdentifierId,
        issuer_certificate_id: Option<CertificateId>,
        purpose: RevocationListPurpose,
        status_list_type: &RevocationMethodId,
    ) -> Result<Option<RevocationList>, DataLayerError>;

    async fn update_formatted_list(
        &self,
        revocation_list_id: &RevocationListId,
        formatted_list: Vec<u8>,
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
        // must be set for non-CRL
        index_on_status_list: Option<usize>,
    ) -> Result<RevocationListEntryId, DataLayerError>;

    async fn update_entry(
        &self,
        id: UpdateRevocationListEntryId,
        request: UpdateRevocationListEntryRequest,
    ) -> Result<(), DataLayerError>;

    /// Links reserved credential entries to their credentials in a single statement.
    /// Fails unless every entry is a credential entry not linked yet.
    async fn link_credential_entries(
        &self,
        links: Vec<(RevocationListEntryId, CredentialId)>,
    ) -> Result<(), DataLayerError>;

    async fn get_entries(
        &self,
        query: RevocationListEntryListQuery,
    ) -> Result<RevocationListEntryList, DataLayerError>;
}

#[async_trait::async_trait]
impl AsyncModelLoader<RevocationList> for Arc<dyn RevocationListRepository> {
    async fn load(&self, id: &RevocationListId) -> Result<RevocationList, DataLayerError> {
        self.get_revocation_list(id).await
    }
}
