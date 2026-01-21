//! `struct`s and `enum`s for revocation method provider.

use serde::Serialize;
use standardized_types::x509::CertificateSerial;
use strum::Display;
use time::OffsetDateTime;

use crate::model::credential::Credential;
use crate::model::proof_schema::ProofInputSchema;
use crate::model::revocation_list::RevocationListEntryStatus;
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
    pub extracted_lvvcs: Vec<DetailCredential>,
    pub proof_input: ProofInputSchema,
}

pub struct CredentialRevocationInfo {
    pub credential_status: CredentialStatus,
    pub serial: Option<CertificateSerial>,
}

#[derive(Clone, Debug, Display, PartialEq)]
pub enum RevocationState {
    Valid,
    Revoked,
    Suspended {
        suspend_end_date: Option<OffsetDateTime>,
    },
}

impl From<RevocationState> for RevocationListEntryStatus {
    fn from(value: RevocationState) -> Self {
        match value {
            RevocationState::Valid => RevocationListEntryStatus::Active,
            RevocationState::Revoked => RevocationListEntryStatus::Revoked,
            RevocationState::Suspended { .. } => RevocationListEntryStatus::Suspended,
        }
    }
}

#[derive(Debug, Default)]
pub struct JsonLdContext {
    pub revokable_credential_type: String,
    pub revokable_credential_subject: String,
    pub url: Option<String>,
}

#[derive(Clone, Default, Serialize)]
pub struct RevocationMethodCapabilities {
    pub operations: Vec<Operation>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Operation {
    Revoke,
    Suspend,
}
