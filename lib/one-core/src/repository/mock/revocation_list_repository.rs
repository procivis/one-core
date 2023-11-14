use crate::{
    model::revocation_list::{RevocationList, RevocationListId, RevocationListRelations},
    repository::error::DataLayerError,
};
use mockall::*;
use shared_types::DidId;

#[derive(Default)]
struct RevocationListRepository;

mock! {
    pub RevocationListRepository {
        pub fn create_revocation_list(
            &self,
            request: RevocationList,
        ) -> Result<RevocationListId, DataLayerError>;
        pub fn get_revocation_list(
            &self,
            id: &RevocationListId,
            relations: &RevocationListRelations
        ) -> Result<RevocationList, DataLayerError>;
        pub fn get_revocation_by_issuer_did_id(
            &self,
            issuer_did_id: &DidId,
            relations: &RevocationListRelations,
        ) -> Result<RevocationList, DataLayerError>;
        pub fn update_credentials(
            &self,
            revocation_list_id: &RevocationListId,
            credentials: Vec<u8>,
        ) -> Result<(), DataLayerError>;
    }
}

#[async_trait::async_trait]
impl crate::repository::revocation_list_repository::RevocationListRepository
    for MockRevocationListRepository
{
    async fn create_revocation_list(
        &self,
        request: RevocationList,
    ) -> Result<RevocationListId, DataLayerError> {
        self.create_revocation_list(request)
    }

    async fn get_revocation_list(
        &self,
        id: &RevocationListId,
        relations: &RevocationListRelations,
    ) -> Result<RevocationList, DataLayerError> {
        self.get_revocation_list(id, relations)
    }

    async fn get_revocation_by_issuer_did_id(
        &self,
        issuer_did_id: &DidId,
        relations: &RevocationListRelations,
    ) -> Result<RevocationList, DataLayerError> {
        self.get_revocation_by_issuer_did_id(issuer_did_id, relations)
    }

    async fn update_credentials(
        &self,
        revocation_list_id: &RevocationListId,
        credentials: Vec<u8>,
    ) -> Result<(), DataLayerError> {
        self.update_credentials(revocation_list_id, credentials)
    }
}
