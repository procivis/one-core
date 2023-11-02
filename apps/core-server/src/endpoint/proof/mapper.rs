use super::dto::{
    CreateProofRequestRestDTO, PresentationDefinitionResponseRestDTO, ProofDetailResponseRestDTO,
    ProofListItemResponseRestDTO, SortableProofColumnRestEnum,
};
use crate::endpoint::proof::dto::{
    PresentationDefinitionRequestGroupResponseRestDTO,
    PresentationDefinitionRequestedCredentialResponseRestDTO,
};
use one_core::service::proof::dto::{
    PresentationDefinitionRequestGroupResponseDTO,
    PresentationDefinitionRequestedCredentialResponseDTO,
};
use one_core::{
    common_mapper::vector_into,
    service::proof::dto::{
        CreateProofRequestDTO, PresentationDefinitionResponseDTO, ProofDetailResponseDTO,
        ProofListItemResponseDTO,
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

impl From<PresentationDefinitionResponseDTO> for PresentationDefinitionResponseRestDTO {
    fn from(value: PresentationDefinitionResponseDTO) -> Self {
        Self {
            credentials: value
                .credentials
                .into_iter()
                .map(|credential| credential.into())
                .collect(),
            request_groups: value
                .request_groups
                .into_iter()
                .map(|request_group| request_group.into())
                .collect(),
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

impl From<PresentationDefinitionRequestGroupResponseDTO>
    for PresentationDefinitionRequestGroupResponseRestDTO
{
    fn from(value: PresentationDefinitionRequestGroupResponseDTO) -> Self {
        Self {
            id: value.id,
            purpose: value.purpose,
            name: value.name,
            rule: value.rule.into(),
            requested_credentials: value
                .requested_credentials
                .into_iter()
                .map(|requested_credential| requested_credential.into())
                .collect(),
        }
    }
}

impl From<PresentationDefinitionRequestedCredentialResponseDTO>
    for PresentationDefinitionRequestedCredentialResponseRestDTO
{
    fn from(value: PresentationDefinitionRequestedCredentialResponseDTO) -> Self {
        Self {
            id: value.id,
            purpose: value.purpose,
            name: value.name,
            fields: value.fields.into_iter().map(|field| field.into()).collect(),
            applicable_credentials: value.applicable_credentials,
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
