use super::model::CredentialRevocationState;
use crate::model::credential::CredentialStateEnum;

impl From<CredentialRevocationState> for CredentialStateEnum {
    fn from(value: CredentialRevocationState) -> Self {
        match value {
            CredentialRevocationState::Valid => CredentialStateEnum::Accepted,
            CredentialRevocationState::Revoked => CredentialStateEnum::Revoked,
            CredentialRevocationState::Suspended { .. } => CredentialStateEnum::Suspended,
        }
    }
}
