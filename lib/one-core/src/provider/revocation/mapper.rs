use super::model::RevocationState;
use crate::model::credential::CredentialStateEnum;

impl From<RevocationState> for CredentialStateEnum {
    fn from(value: RevocationState) -> Self {
        match value {
            RevocationState::Valid => CredentialStateEnum::Accepted,
            RevocationState::Revoked => CredentialStateEnum::Revoked,
            RevocationState::Suspended { .. } => CredentialStateEnum::Suspended,
        }
    }
}
