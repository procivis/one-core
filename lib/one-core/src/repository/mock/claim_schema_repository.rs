use crate::{
    model::claim_schema::{ClaimSchema, ClaimSchemaId, ClaimSchemaRelations},
    repository::error::DataLayerError,
};
use mockall::*;

#[derive(Default)]
struct ClaimSchemaRepository;

mock! {
    pub ClaimSchemaRepository {
        pub fn create_claim_schema_list(
            &self,
            request: Vec<ClaimSchema>,
        ) -> Result<(), DataLayerError>;

        pub fn get_claim_schema_list(
            &self,
            id: Vec<ClaimSchemaId>,
            relations: &ClaimSchemaRelations,
        ) -> Result<Vec<ClaimSchema>, DataLayerError>;
    }
}

#[async_trait::async_trait]
impl crate::repository::claim_schema_repository::ClaimSchemaRepository
    for MockClaimSchemaRepository
{
    async fn create_claim_schema_list(
        &self,
        request: Vec<ClaimSchema>,
    ) -> Result<(), DataLayerError> {
        self.create_claim_schema_list(request)
    }

    async fn get_claim_schema_list(
        &self,
        id: Vec<ClaimSchemaId>,
        relations: &ClaimSchemaRelations,
    ) -> Result<Vec<ClaimSchema>, DataLayerError> {
        self.get_claim_schema_list(id, relations)
    }
}
