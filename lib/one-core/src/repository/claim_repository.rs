use std::collections::HashSet;
use std::sync::Arc;

use shared_types::{ClaimId, CredentialId};

use super::error::DataLayerError;
use crate::model::claim::Claim;
use crate::model::relation::AsyncVecLoader;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait ClaimRepository: Send + Sync {
    /// Store new claims and associate them with a credential. Existing claim IDs
    /// may be shared, but their stored contents must not change.
    async fn create_claim_list(
        &self,
        credential_id: CredentialId,
        request: Vec<Claim>,
    ) -> Result<(), DataLayerError>;

    async fn delete_claims_for_credential(
        &self,
        request: shared_types::CredentialId,
    ) -> Result<(), DataLayerError>;

    async fn delete_claims_for_credentials(
        &self,
        request: HashSet<shared_types::CredentialId>,
    ) -> Result<(), DataLayerError>;

    async fn get_claim_list(&self, id: Vec<ClaimId>) -> Result<Vec<Claim>, DataLayerError>;

    /// Claims belonging to a credential, ordered according to the claim order defined by the
    /// credential schema.
    async fn get_claims_for_credential(
        &self,
        credential_id: CredentialId,
    ) -> Result<Vec<Claim>, DataLayerError>;
}

pub struct CredentialClaimsLoader {
    pub credential_id: CredentialId,
    pub claim_repository: Arc<dyn ClaimRepository>,
}

#[async_trait::async_trait]
impl AsyncVecLoader<Claim> for CredentialClaimsLoader {
    async fn load(&self) -> Result<Vec<Claim>, DataLayerError> {
        self.claim_repository
            .get_claims_for_credential(self.credential_id)
            .await
    }
}
