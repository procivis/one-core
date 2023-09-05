use crate::{
    model::proof_schema::{
        GetProofSchemaList, GetProofSchemaQuery, ProofSchema, ProofSchemaId, ProofSchemaRelations,
    },
    repository::error::DataLayerError,
};
use mockall::*;
use time::OffsetDateTime;

#[derive(Default)]
struct ProofSchemaRepository;

mock! {
    pub ProofSchemaRepository {
        pub fn create_proof_schema(
            &self,
            request: ProofSchema,
        ) -> Result<ProofSchemaId, DataLayerError>;

        pub fn get_proof_schema(
            &self,
            id: &ProofSchemaId,
            relations: &ProofSchemaRelations,
        ) -> Result<ProofSchema, DataLayerError>;

        pub fn get_proof_schema_list(
            &self,
            query_params: GetProofSchemaQuery,
        ) -> Result<GetProofSchemaList, DataLayerError>;

        pub fn delete_proof_schema(
            &self,
            id: &ProofSchemaId,
            deleted_at: OffsetDateTime,
        ) -> Result<(), DataLayerError>;
    }
}

#[async_trait::async_trait]
impl crate::repository::proof_schema_repository::ProofSchemaRepository
    for MockProofSchemaRepository
{
    async fn create_proof_schema(
        &self,
        request: ProofSchema,
    ) -> Result<ProofSchemaId, DataLayerError> {
        self.create_proof_schema(request)
    }

    async fn get_proof_schema(
        &self,
        id: &ProofSchemaId,
        relations: &ProofSchemaRelations,
    ) -> Result<ProofSchema, DataLayerError> {
        self.get_proof_schema(id, relations)
    }

    async fn get_proof_schema_list(
        &self,
        query_params: GetProofSchemaQuery,
    ) -> Result<GetProofSchemaList, DataLayerError> {
        self.get_proof_schema_list(query_params)
    }

    async fn delete_proof_schema(
        &self,
        id: &ProofSchemaId,
        deleted_at: OffsetDateTime,
    ) -> Result<(), DataLayerError> {
        self.delete_proof_schema(id, deleted_at)
    }
}
