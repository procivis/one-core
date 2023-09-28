use super::dto::{
    ClaimBindingDTO, CredentialListItemBindingDTO, CredentialSchemaBindingDTO,
    CredentialStateBindingEnum, ProofRequestBindingDTO, ProofRequestClaimBindingDTO,
};
use crate::{utils::TimestampFormat, CredentialDetailBindingDTO, CredentialListBindingDTO};
use one_core::{
    common_mapper::vector_into,
    service::{
        credential::dto::{
            CredentialDetailResponseDTO, CredentialListItemResponseDTO, CredentialStateEnum,
            DetailCredentialClaimResponseDTO, DetailCredentialSchemaResponseDTO,
            GetCredentialListResponseDTO,
        },
        credential_schema::dto::CredentialSchemaListItemResponseDTO,
        ssi_verifier::dto::{ConnectVerifierResponseDTO, ProofRequestClaimDTO},
    },
};

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

impl From<ConnectVerifierResponseDTO> for ProofRequestBindingDTO {
    fn from(value: ConnectVerifierResponseDTO) -> Self {
        Self {
            claims: value.claims.into_iter().map(|claim| claim.into()).collect(),
            verifier_did: value.verifier_did,
        }
    }
}

impl From<ProofRequestClaimDTO> for ProofRequestClaimBindingDTO {
    fn from(value: ProofRequestClaimDTO) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date.format_timestamp(),
            last_modified: value.last_modified.format_timestamp(),
            key: value.key,
            data_type: value.datatype,
            required: value.required,
            credential_schema: value.credential_schema.into(),
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
