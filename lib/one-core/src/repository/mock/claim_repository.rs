use crate::{
    model::claim::{Claim, ClaimId, ClaimRelations},
    repository::error::DataLayerError,
};
use mockall::*;

#[derive(Default)]
struct ClaimRepository;

mock! {
    pub ClaimRepository {
        pub fn create_claim_list(&self, request: Vec<Claim>) -> Result<(), DataLayerError>;

        pub fn get_claim_list(
            &self,
            id: Vec<ClaimId>,
            relations: &ClaimRelations,
        ) -> Result<Vec<Claim>, DataLayerError>;
    }
}

#[async_trait::async_trait]
impl crate::repository::claim_repository::ClaimRepository for MockClaimRepository {
    async fn create_claim_list(&self, request: Vec<Claim>) -> Result<(), DataLayerError> {
        self.create_claim_list(request)
    }

    async fn get_claim_list(
        &self,
        id: Vec<ClaimId>,
        relations: &ClaimRelations,
    ) -> Result<Vec<Claim>, DataLayerError> {
        self.get_claim_list(id, relations)
    }
}
