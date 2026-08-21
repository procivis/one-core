use crate::model::credential::CredentialStateEnum;
use crate::proto::credential_validity_manager::dto::{ChangeCredentialState, ExpirationState};

impl From<ChangeCredentialState> for CredentialStateEnum {
    fn from(value: ChangeCredentialState) -> CredentialStateEnum {
        match value {
            ChangeCredentialState::Accepted => CredentialStateEnum::Accepted,
            ChangeCredentialState::Revoked => CredentialStateEnum::Revoked,
            ChangeCredentialState::Suspended { .. } => CredentialStateEnum::Suspended,
            ChangeCredentialState::Expiring => CredentialStateEnum::Expiring,
        }
    }
}

impl From<ExpirationState> for CredentialStateEnum {
    fn from(value: ExpirationState) -> Self {
        match value {
            ExpirationState::Accepted => CredentialStateEnum::Accepted,
            ExpirationState::Expiring => CredentialStateEnum::Expiring,
        }
    }
}
