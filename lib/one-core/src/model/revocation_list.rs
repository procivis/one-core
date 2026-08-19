use proc_macros::Model;
use serde::{Deserialize, Serialize};
use shared_types::{
    CredentialId, ManagedInstanceAttestedKeyId, RevocationListEntryId, RevocationListId,
    RevocationMethodId, SignerId,
};
use standardized_types::x509::CertificateSerial;
use strum::Display;
use time::OffsetDateTime;

use crate::model::certificate::Certificate;
use crate::model::identifier::Identifier;
use crate::model::relation::Related;

#[derive(Clone, Debug, Model)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct RevocationList {
    #[model(id)]
    pub id: RevocationListId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub formatted_list: Vec<u8>,
    pub format: StatusListCredentialFormat,
    pub r#type: RevocationMethodId,
    pub purpose: RevocationListPurpose,

    // Relations:
    pub issuer_identifier: Related<Identifier>,
    pub issuer_certificate: Option<Related<Certificate>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Display, Serialize)]
pub enum RevocationListPurpose {
    Revocation,
    Suspension,
    RevocationAndSuspension,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Display, Serialize, Deserialize)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StatusListCredentialFormat {
    Jwt,
    JsonLdClassic,
    X509Crl,
    Cwt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationListEntry {
    pub id: RevocationListEntryId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub entity_info: RevocationListEntityInfo,
    pub index: Option<usize>,
    pub state: RevocationListEntryState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationListEntryState {
    Active,
    Revoked,
    Suspended,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RevocationListEntityId {
    Credential(CredentialId),
    Signature(SignerId, Option<CertificateSerial>),
    WalletUnitAttestedKey(ManagedInstanceAttestedKeyId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RevocationListEntityInfo {
    Credential(CredentialId),
    Signature(SignerId, Option<CertificateSerial>),
    WalletUnitAttestedKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UpdateRevocationListEntryId {
    Credential(CredentialId),
    Id(RevocationListEntryId),
    Index(RevocationListId, usize),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UpdateRevocationListEntryRequest {
    pub state: Option<RevocationListEntryState>,
}
