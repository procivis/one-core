use time::OffsetDateTime;

use super::error::RevocationError;
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

pub(crate) fn revocation_state_from_credential_state(
    state: CredentialStateEnum,
    suspend_end_date: Option<OffsetDateTime>,
) -> Result<RevocationState, RevocationError> {
    Ok(match state {
        CredentialStateEnum::Accepted => RevocationState::Valid,
        CredentialStateEnum::Revoked => RevocationState::Revoked,
        CredentialStateEnum::Suspended => RevocationState::Suspended { suspend_end_date },
        state => {
            return Err(RevocationError::MappingError(format!(
                "Invalid credential state: {state}"
            )));
        }
    })
}
