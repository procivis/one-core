use std::sync::Arc;

use shared_types::ProofSchemaId;
use time::OffsetDateTime;

use super::error::DataLayerError;
use crate::model::proof_schema::{
    GetProofSchemaList, ProofSchema, ProofSchemaListQuery, UpdateProofSchema,
};
use crate::model::relation::AsyncModelLoader;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait ProofSchemaRepository: Send + Sync {
    async fn create_proof_schema(
        &self,
        request: ProofSchema,
    ) -> Result<ProofSchemaId, DataLayerError>;

    async fn get_proof_schema(&self, id: &ProofSchemaId) -> Result<ProofSchema, DataLayerError>;

    async fn get_proof_schema_list(
        &self,
        query_params: ProofSchemaListQuery,
    ) -> Result<GetProofSchemaList, DataLayerError>;

    async fn update_proof_schema(
        &self,
        id: &ProofSchemaId,
        request: UpdateProofSchema,
    ) -> Result<(), DataLayerError>;

    async fn delete_proof_schema(
        &self,
        id: &ProofSchemaId,
        deleted_at: OffsetDateTime,
    ) -> Result<(), DataLayerError>;
}

#[async_trait::async_trait]
impl AsyncModelLoader<ProofSchema> for Arc<dyn ProofSchemaRepository> {
    async fn load(&self, id: &ProofSchemaId) -> Result<ProofSchema, DataLayerError> {
        self.get_proof_schema(id).await
    }
}
