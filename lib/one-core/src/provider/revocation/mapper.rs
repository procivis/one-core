use time::OffsetDateTime;

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

/// The revocation state a credential state stands for, or `None` for a state no revocation list
/// can express - `Expiring` and `Expired`, and the states a credential holds before issuance.
pub(crate) fn revocation_state_from_credential_state(
    state: CredentialStateEnum,
    suspend_end_date: Option<OffsetDateTime>,
) -> Option<RevocationState> {
    match state {
        CredentialStateEnum::Accepted => Some(RevocationState::Valid),
        CredentialStateEnum::Revoked => Some(RevocationState::Revoked),
        CredentialStateEnum::Suspended => Some(RevocationState::Suspended { suspend_end_date }),
        _ => None,
    }
}
