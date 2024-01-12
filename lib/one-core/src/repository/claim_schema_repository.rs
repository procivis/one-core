use super::error::DataLayerError;

use crate::model::claim_schema::{ClaimSchema, ClaimSchemaId, ClaimSchemaRelations};

#[async_trait::async_trait]
pub trait ClaimSchemaRepository: Send + Sync {
    async fn create_claim_schema_list(
        &self,
        request: Vec<ClaimSchema>,
    ) -> Result<(), DataLayerError>;

    async fn get_claim_schema_list(
        &self,
        id: Vec<ClaimSchemaId>,
        relations: &ClaimSchemaRelations,
    ) -> Result<Vec<ClaimSchema>, DataLayerError>;
}
