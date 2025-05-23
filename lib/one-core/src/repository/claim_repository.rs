use std::collections::HashSet;

use super::error::DataLayerError;
use crate::model::claim::{Claim, ClaimId, ClaimRelations};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait ClaimRepository: Send + Sync {
    async fn create_claim_list(&self, request: Vec<Claim>) -> Result<(), DataLayerError>;

    async fn delete_claims_for_credential(
        &self,
        request: shared_types::CredentialId,
    ) -> Result<(), DataLayerError>;

    async fn delete_claims_for_credentials(
        &self,
        request: HashSet<shared_types::CredentialId>,
    ) -> Result<(), DataLayerError>;

    async fn get_claim_list(
        &self,
        id: Vec<ClaimId>,
        relations: &ClaimRelations,
    ) -> Result<Vec<Claim>, DataLayerError>;
}
