use crate::dto::common::EntityShareResponseRestDTO;

use super::dto::{
    CreateProofRequestRestDTO, PresentationDefinitionResponseRestDTO, ProofClaimRestDTO,
    ProofDetailResponseRestDTO, ProofListItemResponseRestDTO, ProofStateRestEnum,
    SortableProofColumnRestEnum,
};
use crate::endpoint::proof::dto::{
    PresentationDefinitionFieldRestDTO, PresentationDefinitionRequestGroupResponseRestDTO,
    PresentationDefinitionRequestedCredentialResponseRestDTO, PresentationDefinitionRuleRestDTO,
    PresentationDefinitionRuleTypeRestEnum,
};
use one_core::service::proof::dto::{
    PresentationDefinitionFieldDTO, PresentationDefinitionRequestGroupResponseDTO,
    PresentationDefinitionRequestedCredentialResponseDTO, PresentationDefinitionRuleDTO,
    PresentationDefinitionRuleTypeEnum,
};
use one_core::{
    common_mapper::vector_into,
    model::{common::EntityShareResponseDTO, proof::ProofStateEnum},
    service::proof::dto::{
        CreateProofRequestDTO, PresentationDefinitionResponseDTO, ProofClaimDTO,
        ProofDetailResponseDTO, ProofListItemResponseDTO,
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

impl From<PresentationDefinitionRuleTypeEnum> for PresentationDefinitionRuleTypeRestEnum {
    fn from(value: PresentationDefinitionRuleTypeEnum) -> Self {
        match value {
            PresentationDefinitionRuleTypeEnum::All => Self::All,
            PresentationDefinitionRuleTypeEnum::Pick => Self::Pick,
        }
    }
}

impl From<PresentationDefinitionRuleDTO> for PresentationDefinitionRuleRestDTO {
    fn from(value: PresentationDefinitionRuleDTO) -> Self {
        Self {
            r#type: value.r#type.into(),
            max: value.max,
            min: value.min,
            count: value.count,
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

impl From<PresentationDefinitionFieldDTO> for PresentationDefinitionFieldRestDTO {
    fn from(value: PresentationDefinitionFieldDTO) -> Self {
        Self {
            id: value.id,
            purpose: value.purpose,
            name: value.name,
            key_map: value.key_map,
            required: value.required,
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

pub(crate) fn share_proof_to_entity_share_response(
    value: EntityShareResponseDTO,
    base_url: &str,
) -> EntityShareResponseRestDTO {
    let protocol = &value.transport;
    EntityShareResponseRestDTO {
        url: format!(
            "{}/ssi/temporary-verifier/v1/connect?protocol={}&proof={}",
            base_url, protocol, value.id
        ),
    }
}
