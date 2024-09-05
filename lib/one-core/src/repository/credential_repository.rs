use shared_types::{CredentialId, DidId};

use super::error::DataLayerError;
use crate::model::claim::ClaimId;
use crate::model::credential::{
    Credential, CredentialRelations, GetCredentialList, GetCredentialQuery, UpdateCredentialRequest,
};
use crate::model::interaction::InteractionId;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait CredentialRepository: Send + Sync {
    async fn create_credential(&self, request: Credential) -> Result<CredentialId, DataLayerError>;

    async fn delete_credential(&self, id: &CredentialId) -> Result<(), DataLayerError>;

    async fn get_credential(
        &self,
        id: &CredentialId,
        relations: &CredentialRelations,
    ) -> Result<Option<Credential>, DataLayerError>;

    async fn get_credentials_by_interaction_id(
        &self,
        interaction_id: &InteractionId,
        relations: &CredentialRelations,
    ) -> Result<Vec<Credential>, DataLayerError>;

    async fn get_credentials_by_issuer_did_id(
        &self,
        issuer_did_id: &DidId,
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

    async fn get_credential_by_claim_id(
        &self,
        claim_id: &ClaimId,
        relations: &CredentialRelations,
    ) -> Result<Option<Credential>, DataLayerError>;

    async fn get_credentials_by_credential_schema_id(
        &self,
        schema_id: String,
        relations: &CredentialRelations,
    ) -> Result<Vec<Credential>, DataLayerError>;
}
