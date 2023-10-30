use super::dto::{
    ClaimBindingDTO, CredentialListItemBindingDTO, CredentialSchemaBindingDTO,
    ProofRequestBindingDTO, ProofRequestClaimBindingDTO,
};
use crate::{
    dto::{
        DidRequestBindingDTO, DidRequestKeysBindingDTO, HandleInvitationResponseBindingEnum,
        KeyRequestBindingDTO, PresentationDefinitionFieldBindingDTO,
        PresentationSubmitCredentialRequestBindingDTO,
    },
    utils::{into_uuid, TimestampFormat},
    CredentialDetailBindingDTO,
};
use one_core::{
    common_mapper::vector_into,
    service::{
        credential::dto::{
            CredentialDetailResponseDTO, CredentialListItemResponseDTO,
            DetailCredentialClaimResponseDTO, DetailCredentialSchemaResponseDTO,
        },
        credential_schema::dto::CredentialSchemaListItemResponseDTO,
        did::dto::{CreateDidRequestDTO, CreateDidRequestKeysDTO},
        error::ServiceError,
        key::dto::KeyRequestDTO,
        proof::dto::{PresentationDefinitionFieldDTO, ProofClaimDTO, ProofDetailResponseDTO},
        ssi_holder::dto::{InvitationResponseDTO, PresentationSubmitCredentialRequestDTO},
    },
};
use serde_json::json;
use std::str::FromStr;
use uuid::Uuid;

impl From<CredentialListItemResponseDTO> for CredentialListItemBindingDTO {
    fn from(value: CredentialListItemResponseDTO) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date.format_timestamp(),
            last_modified: value.last_modified.format_timestamp(),
            issuance_date: value.issuance_date.format_timestamp(),
            revocation_date: value.revocation_date.map(|date| date.format_timestamp()),
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
            revocation_date: value.revocation_date.map(|date| date.format_timestamp()),
            issuer_did: value.issuer_did,
            state: value.state.into(),
            schema: value.schema.into(),
            claims: vector_into(value.claims),
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

impl From<PresentationDefinitionFieldDTO> for PresentationDefinitionFieldBindingDTO {
    fn from(value: PresentationDefinitionFieldDTO) -> Self {
        Self {
            id: value.id,
            name: value.name,
            purpose: value.purpose,
            required: value.required.unwrap_or(true),
            key_map: value.key_map,
        }
    }
}

impl TryFrom<KeyRequestBindingDTO> for KeyRequestDTO {
    type Error = ServiceError;
    fn try_from(request: KeyRequestBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            organisation_id: into_uuid(&request.organisation_id)?,
            key_type: request.key_type.to_owned(),
            key_params: json!(request.key_params),
            name: request.name.to_owned(),
            storage_type: request.storage_type.to_owned(),
            storage_params: json!(request.storage_params),
        })
    }
}

impl TryFrom<DidRequestBindingDTO> for CreateDidRequestDTO {
    type Error = ServiceError;
    fn try_from(request: DidRequestBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            organisation_id: into_uuid(&request.organisation_id)?,
            name: request.name,
            did_method: request.did_method,
            did_type: request.did_type.into(),
            keys: request.keys.try_into()?,
            params: Some(json!(request.params)),
        })
    }
}

impl TryFrom<DidRequestKeysBindingDTO> for CreateDidRequestKeysDTO {
    type Error = ServiceError;
    fn try_from(request: DidRequestKeysBindingDTO) -> Result<Self, Self::Error> {
        let convert = |ids: Vec<String>| -> Result<Vec<Uuid>, Self::Error> {
            ids.iter().map(|id| into_uuid(id)).collect()
        };

        Ok(Self {
            authentication: convert(request.authentication)?,
            assertion: convert(request.assertion)?,
            key_agreement: convert(request.key_agreement)?,
            capability_invocation: convert(request.capability_invocation)?,
            capability_delegation: convert(request.capability_delegation)?,
        })
    }
}
