use crate::functions::Credential;
use crate::utils::TimestampFormat;
use one_core::service::credential::dto::{CredentialListItemResponseDTO, CredentialStateEnum};

use super::dto::CredentialState;

impl From<CredentialListItemResponseDTO> for Credential {
    fn from(value: CredentialListItemResponseDTO) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date.format_timestamp(),
            last_modified: value.last_modified.format_timestamp(),
            issuance_date: value.issuance_date.format_timestamp(),
            issuer_did: value.issuer_did,
            state: value.state.into(),
            claims: vec![], // todo: should get_all_credential_list return claims also?
            schema: value.schema.into(),
        }
    }
}

impl From<CredentialStateEnum> for CredentialState {
    fn from(value: CredentialStateEnum) -> Self {
        match value {
            CredentialStateEnum::Created => CredentialState::Created,
            CredentialStateEnum::Pending => CredentialState::Pending,
            CredentialStateEnum::Offered => CredentialState::Offered,
            CredentialStateEnum::Accepted => CredentialState::Accepted,
            CredentialStateEnum::Rejected => CredentialState::Rejected,
            CredentialStateEnum::Revoked => CredentialState::Revoked,
            CredentialStateEnum::Error => CredentialState::Error,
        }
    }
}
