use super::error::DataLayerError;
use crate::model::{
    credential::{
        Credential, CredentialId, CredentialRelations, GetCredentialList, GetCredentialQuery,
        UpdateCredentialRequest,
    },
    interaction::InteractionId,
};
use uuid::Uuid;

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

    async fn get_credentials_by_issuer_did_id(
        &self,
        issuer_did_id: &Uuid,
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

    async fn get_credentials_by_claim_names(
        &self,
        claim_names: Vec<String>,
        relations: &CredentialRelations,
    ) -> Result<Vec<Credential>, DataLayerError>;
}
