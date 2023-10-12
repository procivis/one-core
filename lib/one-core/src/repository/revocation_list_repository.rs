use uuid::Uuid;

use super::error::DataLayerError;
use crate::model::revocation_list::{RevocationList, RevocationListId, RevocationListRelations};

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
        issuer_did_id: &Uuid,
        relations: &RevocationListRelations,
    ) -> Result<RevocationList, DataLayerError>;
    async fn update_credentials(
        &self,
        revocation_list_id: &RevocationListId,
        credentials: Vec<u8>,
    ) -> Result<(), DataLayerError>;
}
