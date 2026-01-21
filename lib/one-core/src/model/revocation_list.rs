use serde::{Deserialize, Serialize};
use shared_types::{
    CredentialId, RevocationListEntryId, RevocationListId, WalletUnitAttestedKeyId,
};
use standardized_types::x509::CertificateSerial;
use strum::{Display, EnumString};
use time::OffsetDateTime;

use crate::model::certificate::{Certificate, CertificateRelations};
use crate::model::identifier::{Identifier, IdentifierRelations};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationList {
    pub id: RevocationListId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub formatted_list: Vec<u8>,
    pub format: StatusListCredentialFormat,
    pub r#type: StatusListType,
    pub purpose: RevocationListPurpose,

    // Relations:
    pub issuer_identifier: Option<Identifier>,
    pub issuer_certificate: Option<Certificate>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct RevocationListRelations {
    pub issuer_identifier: Option<IdentifierRelations>,
    pub issuer_certificate: Option<CertificateRelations>,
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
}

#[derive(Clone, Debug, Eq, PartialEq, Display, EnumString, Serialize, Deserialize)]
#[strum(serialize_all = "UPPERCASE")]
#[serde(rename_all = "UPPERCASE")]
pub enum StatusListType {
    BitstringStatusList,
    TokenStatusList,
    Crl,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationListEntry {
    pub id: RevocationListEntryId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub entity_info: RevocationListEntityInfo,
    pub index: Option<usize>,
    pub status: RevocationListEntryStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RevocationListEntryStatus {
    Active,
    Revoked,
    Suspended,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RevocationListEntityId {
    Credential(CredentialId),
    Signature(String, Option<CertificateSerial>),
    WalletUnitAttestedKey(WalletUnitAttestedKeyId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RevocationListEntityInfo {
    Credential(CredentialId),
    Signature(String, Option<CertificateSerial>),
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
    pub status: Option<RevocationListEntryStatus>,
}
