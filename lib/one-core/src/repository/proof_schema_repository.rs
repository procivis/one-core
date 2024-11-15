use shared_types::ProofSchemaId;
use time::OffsetDateTime;

use super::error::DataLayerError;
use crate::model::proof_schema::{
    GetProofSchemaList, GetProofSchemaQuery, ProofSchema, ProofSchemaRelations,
};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait ProofSchemaRepository: Send + Sync {
    async fn create_proof_schema(
        &self,
        request: ProofSchema,
    ) -> Result<ProofSchemaId, DataLayerError>;

    async fn get_proof_schema(
        &self,
        id: &ProofSchemaId,
        relations: &ProofSchemaRelations,
    ) -> Result<Option<ProofSchema>, DataLayerError>;

    async fn get_proof_schema_list(
        &self,
        query_params: GetProofSchemaQuery,
    ) -> Result<GetProofSchemaList, DataLayerError>;

    async fn delete_proof_schema(
        &self,
        id: &ProofSchemaId,
        deleted_at: OffsetDateTime,
    ) -> Result<(), DataLayerError>;
}
