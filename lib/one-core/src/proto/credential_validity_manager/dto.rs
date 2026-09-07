use time::OffsetDateTime;

use crate::provider::revocation::model::RevocationState;

#[derive(Clone, Copy, Debug)]
pub enum ChangeCredentialState {
    Accepted,
    Revoked,
    Suspended {
        suspend_end_date: Option<OffsetDateTime>,
    },
    Expiring,
}

impl ChangeCredentialState {
    /// The state to publish to the revocation method, or `None` for `Expiring` - a flag on the
    /// batch parent that has no equivalent in any revocation list.
    pub(super) fn revocation_state(self) -> Option<RevocationState> {
        match self {
            ChangeCredentialState::Accepted => Some(RevocationState::Valid),
            ChangeCredentialState::Revoked => Some(RevocationState::Revoked),
            ChangeCredentialState::Suspended { suspend_end_date } => {
                Some(RevocationState::Suspended { suspend_end_date })
            }
            ChangeCredentialState::Expiring => None,
        }
    }
}
