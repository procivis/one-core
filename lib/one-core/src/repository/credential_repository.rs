use std::collections::HashSet;
use std::sync::Arc;

use shared_types::{CredentialId, InteractionId};

use super::error::DataLayerError;
use crate::model::credential::{
    Credential, CredentialListQuery, GetCredentialList, UpdateCredentialRequest,
};
use crate::model::relation::AsyncModelLoader;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait CredentialRepository: Send + Sync {
    async fn create_credential(&self, request: Credential) -> Result<CredentialId, DataLayerError>;

    /// Create credentials and their claims atomically, preserving input ID order.
    /// Parents may be supplied together with their items, in any order.
    async fn create_credentials(
        &self,
        requests: Vec<Credential>,
    ) -> Result<Vec<CredentialId>, DataLayerError>;

    async fn delete_credentials(&self, credentials: &[Credential]) -> Result<(), DataLayerError>;

    async fn delete_credential_blobs(
        &self,
        request: HashSet<shared_types::CredentialId>,
    ) -> Result<(), DataLayerError>;

    async fn get_credential(&self, id: &CredentialId) -> Result<Credential, DataLayerError>;

    async fn get_credentials_by_interaction_id(
        &self,
        interaction_id: &InteractionId,
    ) -> Result<Vec<Credential>, DataLayerError>;

    async fn get_credential_list(
        &self,
        query_params: CredentialListQuery,
    ) -> Result<GetCredentialList, DataLayerError>;

    async fn update_credential(
        &self,
        credential_id: CredentialId,
        credential: UpdateCredentialRequest,
    ) -> Result<(), DataLayerError>;

    async fn get_credentials_by_claim_names(
        &self,
        claim_names: Vec<String>,
    ) -> Result<Vec<Credential>, DataLayerError>;
}

#[async_trait::async_trait]
impl AsyncModelLoader<Credential> for Arc<dyn CredentialRepository> {
    async fn load(&self, id: &CredentialId) -> Result<Credential, DataLayerError> {
        self.get_credential(id).await
    }
}
