use super::dto::{CreateProofSchemaRequestRestDTO, GetProofSchemaResponseRestDTO};
use one_core::{
    common_mapper::vector_into,
    service::proof_schema::dto::{CreateProofSchemaRequestDTO, GetProofSchemaResponseDTO},
};

impl From<GetProofSchemaResponseDTO> for GetProofSchemaResponseRestDTO {
    fn from(value: GetProofSchemaResponseDTO) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            organisation_id: value.organisation_id,
            expire_duration: value.expire_duration,
            claim_schemas: vector_into(value.claim_schemas),
        }
    }
}

impl From<CreateProofSchemaRequestRestDTO> for CreateProofSchemaRequestDTO {
    fn from(value: CreateProofSchemaRequestRestDTO) -> Self {
        Self {
            name: value.name,
            organisation_id: value.organisation_id,
            expire_duration: value.expire_duration,
            claim_schemas: vector_into(value.claim_schemas),
        }
    }
}
