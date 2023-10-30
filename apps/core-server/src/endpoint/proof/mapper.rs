use super::dto::{
    CreateProofRequestRestDTO, ProofDetailResponseRestDTO, ProofListItemResponseRestDTO,
    SortableProofColumnRestEnum,
};
use one_core::{
    common_mapper::vector_into,
    service::proof::dto::{
        CreateProofRequestDTO, ProofDetailResponseDTO, ProofListItemResponseDTO,
    },
};

impl From<ProofDetailResponseDTO> for ProofDetailResponseRestDTO {
    fn from(value: ProofDetailResponseDTO) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            issuance_date: value.issuance_date,
            requested_date: value.requested_date,
            completed_date: value.completed_date,
            verifier_did: value.verifier_did,
            transport: value.transport,
            state: value.state.into(),
            organisation_id: value.organisation_id,
            schema: value.schema.map(|schema| schema.into()),
            claims: vector_into(value.claims),
        }
    }
}

impl From<ProofListItemResponseDTO> for ProofListItemResponseRestDTO {
    fn from(value: ProofListItemResponseDTO) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            issuance_date: value.issuance_date,
            requested_date: value.requested_date,
            completed_date: value.completed_date,
            verifier_did: value.verifier_did,
            transport: value.transport,
            state: value.state.into(),
            schema: value.schema.map(|schema| schema.into()),
        }
    }
}

impl From<SortableProofColumnRestEnum> for one_core::model::proof::SortableProofColumn {
    fn from(value: SortableProofColumnRestEnum) -> Self {
        match value {
            SortableProofColumnRestEnum::ProofSchemaName => Self::SchemaName,
            SortableProofColumnRestEnum::VerifierDid => Self::VerifierDid,
            SortableProofColumnRestEnum::CreatedDate => Self::CreatedDate,
            SortableProofColumnRestEnum::State => Self::State,
        }
    }
}

impl From<CreateProofRequestRestDTO> for CreateProofRequestDTO {
    fn from(value: CreateProofRequestRestDTO) -> Self {
        Self {
            proof_schema_id: value.proof_schema_id,
            verifier_did_id: value.verifier_did,
            transport: value.transport,
        }
    }
}
