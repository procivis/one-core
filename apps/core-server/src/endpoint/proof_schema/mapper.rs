use super::dto::{
    ClaimProofSchemaRequestRestDTO, CreateProofSchemaRequestRestDTO,
    GetProofSchemaListItemResponseRestDTO, GetProofSchemaResponseRestDTO,
    ProofClaimSchemaResponseRestDTO, SortableProofSchemaColumnRestEnum,
};
use one_core::{
    common_mapper::vector_into,
    service::proof_schema::dto::{
        CreateProofSchemaClaimRequestDTO, CreateProofSchemaRequestDTO, GetProofSchemaListItemDTO,
        GetProofSchemaResponseDTO, ProofClaimSchemaResponseDTO,
    },
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

impl From<GetProofSchemaListItemDTO> for GetProofSchemaListItemResponseRestDTO {
    fn from(value: GetProofSchemaListItemDTO) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            expire_duration: value.expire_duration,
        }
    }
}

impl From<ProofClaimSchemaResponseDTO> for ProofClaimSchemaResponseRestDTO {
    fn from(value: ProofClaimSchemaResponseDTO) -> Self {
        Self {
            id: value.id,
            required: value.required,
            key: value.key,
            data_type: value.data_type,
            credential_schema: value.credential_schema.into(),
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

impl From<ClaimProofSchemaRequestRestDTO> for CreateProofSchemaClaimRequestDTO {
    fn from(value: ClaimProofSchemaRequestRestDTO) -> Self {
        Self {
            id: value.id,
            required: value.required,
        }
    }
}

impl From<SortableProofSchemaColumnRestEnum>
    for one_core::model::proof_schema::SortableProofSchemaColumn
{
    fn from(value: SortableProofSchemaColumnRestEnum) -> Self {
        match value {
            SortableProofSchemaColumnRestEnum::Name => Self::Name,
            SortableProofSchemaColumnRestEnum::CreatedDate => Self::CreatedDate,
        }
    }
}
