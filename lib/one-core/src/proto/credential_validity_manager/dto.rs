use time::OffsetDateTime;

use crate::model::credential::{Credential, CredentialStateEnum};
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

#[derive(Clone, Copy, Debug)]
pub(super) enum ExpirationState {
    Accepted,
    Expiring,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum ChangeType {
    Expiration(ExpirationState),
    Revocation(RevocationState),
}

impl ChangeCredentialState {
    pub(super) fn to_change_type(self, credential: &Credential) -> ChangeType {
        match self {
            ChangeCredentialState::Accepted
                if credential.state == CredentialStateEnum::Expiring =>
            {
                ChangeType::Expiration(ExpirationState::Accepted)
            }
            ChangeCredentialState::Expiring => ChangeType::Expiration(ExpirationState::Expiring),
            ChangeCredentialState::Accepted => ChangeType::Revocation(RevocationState::Valid),
            ChangeCredentialState::Revoked => ChangeType::Revocation(RevocationState::Revoked),
            ChangeCredentialState::Suspended { suspend_end_date } => {
                ChangeType::Revocation(RevocationState::Suspended { suspend_end_date })
            }
        }
    }
}
