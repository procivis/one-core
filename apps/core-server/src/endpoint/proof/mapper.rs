use super::dto::{
    CreateProofRequestRestDTO, ProofClaimRestDTO, ProofDetailResponseRestDTO,
    ProofListItemResponseRestDTO, ProofStateRestEnum, ShareProofResponseRestDTO,
    SortableProofColumnRestEnum,
};
use one_core::{
    common_mapper::vector_into,
    model::proof::ProofStateEnum,
    service::proof::dto::{
        CreateProofRequestDTO, ProofClaimDTO, ProofDetailResponseDTO, ProofListItemResponseDTO,
        ShareProofResponseDTO,
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
            schema: value.schema.into(),
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
            schema: value.schema.into(),
        }
    }
}

impl From<ProofStateEnum> for ProofStateRestEnum {
    fn from(value: ProofStateEnum) -> Self {
        match value {
            ProofStateEnum::Created => Self::Created,
            ProofStateEnum::Pending => Self::Pending,
            ProofStateEnum::Offered => Self::Offered,
            ProofStateEnum::Accepted => Self::Accepted,
            ProofStateEnum::Rejected => Self::Rejected,
            ProofStateEnum::Error => Self::Error,
        }
    }
}

impl From<ProofClaimDTO> for ProofClaimRestDTO {
    fn from(value: ProofClaimDTO) -> Self {
        Self {
            schema: value.schema.into(),
            value: value.value,
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

impl From<ShareProofResponseDTO> for ShareProofResponseRestDTO {
    fn from(value: ShareProofResponseDTO) -> Self {
        Self { url: value.url }
    }
}