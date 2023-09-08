use crate::model::credential::{
    Credential, CredentialId, CredentialRelations, CredentialState, GetCredentialList,
    GetCredentialQuery,
};

use super::error::DataLayerError;

#[async_trait::async_trait]
pub trait CredentialRepository {
    async fn create_credential(&self, request: Credential) -> Result<CredentialId, DataLayerError>;

    async fn get_all_credential_list(&self) -> Result<Vec<Credential>, DataLayerError>;

    async fn get_credential(
        &self,
        id: &CredentialId,
        relations: &CredentialRelations,
    ) -> Result<Credential, DataLayerError>;

    async fn get_credential_list(
        &self,
        query_params: GetCredentialQuery,
    ) -> Result<GetCredentialList, DataLayerError>;

    async fn set_credential_state(
        &self,
        id: &CredentialId,
        state: CredentialState,
    ) -> Result<(), DataLayerError>;
}
