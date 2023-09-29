use super::dto::{
    ClaimBindingDTO, CredentialListItemBindingDTO, CredentialSchemaBindingDTO,
    CredentialStateBindingEnum, ProofRequestBindingDTO, ProofRequestClaimBindingDTO,
};
use crate::{
    dto::{HandleInvitationResponseBindingEnum, PresentationSubmitCredentialRequestBindingDTO},
    utils::TimestampFormat,
    CredentialDetailBindingDTO, CredentialListBindingDTO,
};
use one_core::{
    common_mapper::vector_into,
    service::{
        credential::dto::{
            CredentialDetailResponseDTO, CredentialListItemResponseDTO, CredentialStateEnum,
            DetailCredentialClaimResponseDTO, DetailCredentialSchemaResponseDTO,
            GetCredentialListResponseDTO,
        },
        credential_schema::dto::CredentialSchemaListItemResponseDTO,
        error::ServiceError,
        proof::dto::{ProofClaimDTO, ProofDetailResponseDTO},
        ssi_holder::dto::{InvitationResponseDTO, PresentationSubmitCredentialRequestDTO},
    },
};
use std::str::FromStr;
use uuid::Uuid;

impl From<CredentialListItemResponseDTO> for CredentialListItemBindingDTO {
    fn from(value: CredentialListItemResponseDTO) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date.format_timestamp(),
            last_modified: value.last_modified.format_timestamp(),
            issuance_date: value.issuance_date.format_timestamp(),
            issuer_did: value.issuer_did,
            state: value.state.into(),
            schema: value.schema.into(),
        }
    }
}

impl From<CredentialDetailResponseDTO> for CredentialDetailBindingDTO {
    fn from(value: CredentialDetailResponseDTO) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date.format_timestamp(),
            last_modified: value.last_modified.format_timestamp(),
            issuance_date: value.issuance_date.format_timestamp(),
            issuer_did: value.issuer_did,
            state: value.state.into(),
            schema: value.schema.into(),
            claims: vector_into(value.claims),
        }
    }
}

impl From<CredentialStateEnum> for CredentialStateBindingEnum {
    fn from(value: CredentialStateEnum) -> Self {
        match value {
            CredentialStateEnum::Created => Self::Created,
            CredentialStateEnum::Pending => Self::Pending,
            CredentialStateEnum::Offered => Self::Offered,
            CredentialStateEnum::Accepted => Self::Accepted,
            CredentialStateEnum::Rejected => Self::Rejected,
            CredentialStateEnum::Revoked => Self::Revoked,
            CredentialStateEnum::Error => Self::Error,
        }
    }
}

impl From<CredentialSchemaListItemResponseDTO> for CredentialSchemaBindingDTO {
    fn from(value: CredentialSchemaListItemResponseDTO) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date.format_timestamp(),
            last_modified: value.last_modified.format_timestamp(),
            name: value.name,
            format: value.format,
            revocation_method: value.revocation_method,
        }
    }
}

impl From<DetailCredentialSchemaResponseDTO> for CredentialSchemaBindingDTO {
    fn from(value: DetailCredentialSchemaResponseDTO) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date.format_timestamp(),
            last_modified: value.last_modified.format_timestamp(),
            name: value.name,
            format: value.format,
            revocation_method: value.revocation_method,
        }
    }
}

impl From<DetailCredentialClaimResponseDTO> for ClaimBindingDTO {
    fn from(value: DetailCredentialClaimResponseDTO) -> Self {
        Self {
            id: value.schema.id.to_string(),
            key: value.schema.key,
            data_type: value.schema.datatype,
            value: value.value,
        }
    }
}

impl From<ProofDetailResponseDTO> for ProofRequestBindingDTO {
    fn from(value: ProofDetailResponseDTO) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date.format_timestamp(),
            last_modified: value.last_modified.format_timestamp(),
            claims: value.claims.into_iter().map(|claim| claim.into()).collect(),
            verifier_did: value.verifier_did,
            transport: value.transport,
        }
    }
}

impl From<ProofClaimDTO> for ProofRequestClaimBindingDTO {
    fn from(value: ProofClaimDTO) -> Self {
        Self {
            id: value.schema.id.to_string(),
            key: value.schema.key,
            data_type: value.schema.data_type,
            required: value.schema.required,
            credential_schema: value.schema.credential_schema.into(),
        }
    }
}

impl From<GetCredentialListResponseDTO> for CredentialListBindingDTO {
    fn from(value: GetCredentialListResponseDTO) -> Self {
        Self {
            values: vector_into(value.values),
            total_pages: value.total_pages,
            total_items: value.total_items,
        }
    }
}

impl From<InvitationResponseDTO> for HandleInvitationResponseBindingEnum {
    fn from(value: InvitationResponseDTO) -> Self {
        match value {
            InvitationResponseDTO::Credential {
                credential_ids,
                interaction_id,
            } => Self::CredentialIssuance {
                interaction_id: interaction_id.to_string(),
                credential_ids: credential_ids.iter().map(|item| item.to_string()).collect(),
            },
            InvitationResponseDTO::ProofRequest {
                interaction_id,
                proof_id,
            } => Self::ProofRequest {
                interaction_id: interaction_id.to_string(),
                proof_id: proof_id.to_string(),
            },
        }
    }
}

impl TryFrom<PresentationSubmitCredentialRequestBindingDTO>
    for PresentationSubmitCredentialRequestDTO
{
    type Error = ServiceError;
    fn try_from(value: PresentationSubmitCredentialRequestBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            credential_id: Uuid::from_str(&value.credential_id)
                .map_err(|e| ServiceError::MappingError(e.to_string()))?,
            submit_claims: value.submit_claims,
        })
    }
}
