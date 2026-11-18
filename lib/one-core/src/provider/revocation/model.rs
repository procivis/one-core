//! `struct`s and `enum`s for revocation method provider.

use serde::{Deserialize, Serialize};
use shared_types::RevocationListEntryId;
use standardized_types::x509::CertificateSerial;
use strum::Display;
use time::OffsetDateTime;

use crate::model::revocation_list::RevocationListEntryState;
use crate::provider::credential_formatter::model::CredentialStatus;

pub struct CredentialRevocationInfo {
    pub credential_status: CredentialStatus,
    pub serial: Option<CertificateSerial>,
}

/// Status list entries reserved for a credential that is not persisted yet
pub struct ReservedEntries {
    /// Not linked to the credential: link them via `UpdateRevocationListEntryRequest.credential_id`
    /// once it is persisted
    pub entry_ids: Vec<RevocationListEntryId>,
    pub revocation_info: CredentialRevocationInfo,
}

#[derive(Clone, Copy, Debug, Display, PartialEq)]
pub enum RevocationState {
    Valid,
    Revoked,
    Suspended {
        suspend_end_date: Option<OffsetDateTime>,
    },
}

impl From<RevocationState> for RevocationListEntryState {
    fn from(value: RevocationState) -> Self {
        match value {
            RevocationState::Valid => RevocationListEntryState::Active,
            RevocationState::Revoked => RevocationListEntryState::Revoked,
            RevocationState::Suspended { .. } => RevocationListEntryState::Suspended,
        }
    }
}

#[derive(Clone, Default, Serialize)]
pub struct RevocationMethodCapabilities {
    pub operations: Vec<Operation>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, Display)]
#[serde(rename_all = "UPPERCASE")]
pub enum Operation {
    Revoke,
    Suspend,
}
