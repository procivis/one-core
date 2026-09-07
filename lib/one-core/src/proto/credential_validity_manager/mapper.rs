use crate::model::credential::CredentialStateEnum;
use crate::proto::credential_validity_manager::dto::ChangeCredentialState;

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
