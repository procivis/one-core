use std::collections::HashMap;

use super::dto::{ClaimBindingDTO, CredentialSchemaBindingDTO};
use crate::{
    dto::{
        CredentialDetailBindingDTO, CredentialListItemBindingDTO, DidRequestBindingDTO,
        DidRequestKeysBindingDTO, HandleInvitationResponseBindingEnum, KeyRequestBindingDTO,
        ProofRequestBindingDTO,
    },
    utils::{into_id, TimestampFormat},
    HistoryListItemBindingDTO, HistoryMetadataBinding,
};
use dto_mapper::convert_inner;
use one_core::service::{
    credential::dto::{
        CredentialDetailResponseDTO, CredentialListItemResponseDTO,
        DetailCredentialClaimResponseDTO, DetailCredentialSchemaResponseDTO,
    },
    did::dto::{CreateDidRequestDTO, CreateDidRequestKeysDTO},
    error::ServiceError,
    history::dto::{HistoryMetadataResponse, HistoryResponseDTO},
    key::dto::KeyRequestDTO,
    proof::dto::ProofDetailResponseDTO,
    ssi_holder::dto::InvitationResponseDTO,
};
use serde_json::json;
use shared_types::KeyId;

pub(crate) fn serialize_config_entity(
    input: HashMap<String, serde_json::Value>,
) -> HashMap<String, String> {
    input
        .into_iter()
        .map(|(key, value)| (key, value.to_string()))
        .collect()
}

impl From<CredentialDetailResponseDTO> for CredentialDetailBindingDTO {
    fn from(value: CredentialDetailResponseDTO) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date.format_timestamp(),
            issuance_date: value.issuance_date.format_timestamp(),
            last_modified: value.last_modified.format_timestamp(),
            revocation_date: value.revocation_date.map(|inner| inner.format_timestamp()),
            issuer_did: value.issuer_did.map(|inner| inner.did.to_string()),
            state: value.state.into(),
            schema: value.schema.into(),
            claims: convert_inner(value.claims),
            redirect_uri: value.redirect_uri,
            role: value.role.into(),
            lvvc_issuance_date: value
                .lvvc_issuance_date
                .map(|lvvc_issuance_date| lvvc_issuance_date.format_timestamp()),
            suspend_end_date: value
                .suspend_end_date
                .map(|suspend_end_date| suspend_end_date.format_timestamp()),
        }
    }
}

impl From<CredentialListItemResponseDTO> for CredentialListItemBindingDTO {
    fn from(value: CredentialListItemResponseDTO) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date.format_timestamp(),
            issuance_date: value.issuance_date.format_timestamp(),
            last_modified: value.last_modified.format_timestamp(),
            revocation_date: value.revocation_date.map(|inner| inner.format_timestamp()),
            issuer_did: value.issuer_did.map(|inner| inner.did.to_string()),
            state: value.state.into(),
            schema: value.schema.into(),
            role: value.role.into(),
            suspend_end_date: value
                .suspend_end_date
                .map(|suspend_end_date| suspend_end_date.format_timestamp()),
        }
    }
}

impl From<ProofDetailResponseDTO> for ProofRequestBindingDTO {
    fn from(value: ProofDetailResponseDTO) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date.format_timestamp(),
            last_modified: value.last_modified.format_timestamp(),
            // will be fixed in ONE-1735
            claims: vec![],
            verifier_did: value.verifier_did.map(|inner| inner.did.to_string()),
            transport: value.transport,
            redirect_uri: value.redirect_uri,
            credentials: convert_inner(value.credentials),
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
            wallet_storage_type: convert_inner(value.wallet_storage_type),
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

impl From<InvitationResponseDTO> for HandleInvitationResponseBindingEnum {
    fn from(value: InvitationResponseDTO) -> Self {
        match value {
            InvitationResponseDTO::Credential {
                credentials,
                interaction_id,
            } => Self::CredentialIssuance {
                interaction_id: interaction_id.to_string(),
                credential_ids: credentials.iter().map(|item| item.id.to_string()).collect(),
            },
            InvitationResponseDTO::ProofRequest {
                interaction_id,
                proof,
            } => Self::ProofRequest {
                interaction_id: interaction_id.to_string(),
                proof_id: proof.id.to_string(),
            },
        }
    }
}

impl TryFrom<KeyRequestBindingDTO> for KeyRequestDTO {
    type Error = ServiceError;
    fn try_from(request: KeyRequestBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            organisation_id: into_id(&request.organisation_id)?,
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
            organisation_id: into_id(&request.organisation_id)?,
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
        let convert = |ids: Vec<String>| -> Result<Vec<KeyId>, Self::Error> {
            ids.iter().map(|id| into_id(id)).collect()
        };

        Ok(Self {
            authentication: convert(request.authentication)?,
            assertion_method: convert(request.assertion_method)?,
            key_agreement: convert(request.key_agreement)?,
            capability_invocation: convert(request.capability_invocation)?,
            capability_delegation: convert(request.capability_delegation)?,
        })
    }
}

impl From<HistoryMetadataResponse> for HistoryMetadataBinding {
    fn from(value: HistoryMetadataResponse) -> Self {
        match value {
            HistoryMetadataResponse::UnexportableEntities(value) => Self::UnexportableEntities {
                value: value.into(),
            },
        }
    }
}

impl From<HistoryResponseDTO> for HistoryListItemBindingDTO {
    fn from(value: HistoryResponseDTO) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date.format_timestamp(),
            action: value.action.into(),
            entity_id: value.entity_id.map(|id| id.to_string()),
            entity_type: value.entity_type.into(),
            metadata: convert_inner(value.metadata),
            organisation_id: value.organisation_id.to_string(),
        }
    }
}
