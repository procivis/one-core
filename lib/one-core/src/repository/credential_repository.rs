use crate::model::{
    credential::{
        Credential, CredentialId, CredentialRelations, GetCredentialList, GetCredentialQuery,
        UpdateCredentialRequest,
    },
    interaction::InteractionId,
};

use super::error::DataLayerError;

#[async_trait::async_trait]
pub trait CredentialRepository {
    async fn create_credential(&self, request: Credential) -> Result<CredentialId, DataLayerError>;

    async fn get_credential(
        &self,
        id: &CredentialId,
        relations: &CredentialRelations,
    ) -> Result<Credential, DataLayerError>;

    async fn get_credentials_by_interaction_id(
        &self,
        interaction_id: &InteractionId,
        relations: &CredentialRelations,
    ) -> Result<Vec<Credential>, DataLayerError>;

    async fn get_credential_list(
        &self,
        query_params: GetCredentialQuery,
    ) -> Result<GetCredentialList, DataLayerError>;

    async fn update_credential(
        &self,
        credential: UpdateCredentialRequest,
    ) -> Result<(), DataLayerError>;
}
