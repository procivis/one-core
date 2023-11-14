use shared_types::DidId;

use crate::model::revocation_list::{RevocationList, RevocationListId, RevocationListRelations};

use super::error::DataLayerError;

#[async_trait::async_trait]
pub trait RevocationListRepository {
    async fn create_revocation_list(
        &self,
        request: RevocationList,
    ) -> Result<RevocationListId, DataLayerError>;
    async fn get_revocation_list(
        &self,
        id: &RevocationListId,
        relations: &RevocationListRelations,
    ) -> Result<RevocationList, DataLayerError>;
    async fn get_revocation_by_issuer_did_id(
        &self,
        issuer_did_id: &DidId,
        relations: &RevocationListRelations,
    ) -> Result<RevocationList, DataLayerError>;
    async fn update_credentials(
        &self,
        revocation_list_id: &RevocationListId,
        credentials: Vec<u8>,
    ) -> Result<(), DataLayerError>;
}
