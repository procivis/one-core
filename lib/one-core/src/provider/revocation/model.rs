//! `struct`s and `enum`s for revocation method provider.

use serde::{Deserialize, Serialize};
use standardized_types::x509::CertificateSerial;
use strum::Display;
use time::OffsetDateTime;

use crate::model::credential::Credential;
use crate::model::proof_schema::ProofInputSchema;
use crate::model::revocation_list::RevocationListEntryState;
use crate::provider::credential_formatter::model::{CredentialStatus, DetailCredential};

#[derive(Clone)]
pub enum CredentialDataByRole {
    // issuer variant is missing because issuers should simply check the credential state
    Holder(Box<Credential>),
    Verifier(Box<VerifierCredentialData>),
}

#[derive(Debug, Clone)]
pub struct VerifierCredentialData {
    pub credential: DetailCredential,
    pub proof_input: ProofInputSchema,
}

pub struct CredentialRevocationInfo {
    pub credential_status: CredentialStatus,
    pub serial: Option<CertificateSerial>,
}

#[derive(Clone, Copy, Debug, Display, PartialEq)]
pub enum RevocationState {
    Valid,
    Revoked,
    Suspended {
        suspend_end_date: Option<OffsetDateTime>,
    },
    Expired,
}

impl From<RevocationState> for RevocationListEntryState {
    fn from(value: RevocationState) -> Self {
        match value {
            RevocationState::Valid => RevocationListEntryState::Active,
            RevocationState::Revoked => RevocationListEntryState::Revoked,
            RevocationState::Suspended { .. } => RevocationListEntryState::Suspended,
            RevocationState::Expired => RevocationListEntryState::Revoked,
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
