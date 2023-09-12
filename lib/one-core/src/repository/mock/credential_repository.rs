use crate::{
    model::credential::{
        Credential, CredentialId, CredentialRelations, GetCredentialList, GetCredentialQuery,
        UpdateCredentialRequest,
    },
    repository::error::DataLayerError,
};
use mockall::*;

#[derive(Default)]
struct CredentialRepository;

mock! {
    pub CredentialRepository {
        pub fn create_credential(&self, request: Credential) -> Result<CredentialId, DataLayerError>;

        pub fn get_all_credential_list(&self) -> Result<Vec<Credential>, DataLayerError>;

        pub fn get_credential(
            &self,
            id: &CredentialId,
            relations: &CredentialRelations,
        ) -> Result<Credential, DataLayerError>;

        pub fn get_credential_list(
            &self,
            query_params: GetCredentialQuery,
        ) -> Result<GetCredentialList, DataLayerError>;

        pub fn update_credential(
            &self,
            credential: UpdateCredentialRequest,
        ) -> Result<(), DataLayerError>;
    }
}

#[async_trait::async_trait]
impl crate::repository::credential_repository::CredentialRepository for MockCredentialRepository {
    async fn create_credential(&self, request: Credential) -> Result<CredentialId, DataLayerError> {
        self.create_credential(request)
    }

    async fn get_all_credential_list(&self) -> Result<Vec<Credential>, DataLayerError> {
        self.get_all_credential_list()
    }

    async fn get_credential(
        &self,
        id: &CredentialId,
        relations: &CredentialRelations,
    ) -> Result<Credential, DataLayerError> {
        self.get_credential(id, relations)
    }

    async fn get_credential_list(
        &self,
        query_params: GetCredentialQuery,
    ) -> Result<GetCredentialList, DataLayerError> {
        self.get_credential_list(query_params)
    }

    async fn update_credential(
        &self,
        credential: UpdateCredentialRequest,
    ) -> Result<(), DataLayerError> {
        self.update_credential(credential)
    }
}
