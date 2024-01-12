use super::error::DataLayerError;

use crate::model::claim::{Claim, ClaimId, ClaimRelations};

#[async_trait::async_trait]
pub trait ClaimRepository: Send + Sync {
    async fn create_claim_list(&self, request: Vec<Claim>) -> Result<(), DataLayerError>;

    async fn get_claim_list(
        &self,
        id: Vec<ClaimId>,
        relations: &ClaimRelations,
    ) -> Result<Vec<Claim>, DataLayerError>;
}
