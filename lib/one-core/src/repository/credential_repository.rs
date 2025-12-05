use std::collections::HashSet;

use shared_types::{ClaimId, CredentialId};

use super::error::DataLayerError;
use crate::model::credential::{
    Credential, CredentialRelations, GetCredentialList, GetCredentialQuery, UpdateCredentialRequest,
};
use crate::model::interaction::InteractionId;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait CredentialRepository: Send + Sync {
    async fn create_credential(&self, request: Credential) -> Result<CredentialId, DataLayerError>;

    async fn delete_credential(&self, credential: &Credential) -> Result<(), DataLayerError>;

    async fn delete_credential_blobs(
        &self,
        request: HashSet<shared_types::CredentialId>,
    ) -> Result<(), DataLayerError>;

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

    async fn get_credential_list(
        &self,
        query_params: GetCredentialQuery,
    ) -> Result<GetCredentialList, DataLayerError>;

    async fn update_credential(
        &self,
        credential_id: CredentialId,
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
}
