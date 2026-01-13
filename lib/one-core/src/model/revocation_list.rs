use serde::{Deserialize, Serialize};
use shared_types::{
    CredentialId, RevocationListEntryId, RevocationListId, WalletUnitAttestedKeyId,
};
use strum::{Display, EnumString};
use time::OffsetDateTime;

use crate::model::identifier::{Identifier, IdentifierRelations};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationList {
    pub id: RevocationListId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub credentials: Vec<u8>,
    pub format: StatusListCredentialFormat,
    pub r#type: StatusListType,
    pub purpose: RevocationListPurpose,

    // Relations:
    pub issuer_identifier: Option<Identifier>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct RevocationListRelations {
    pub issuer_identifier: Option<IdentifierRelations>,
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
}

#[derive(Clone, Debug, Eq, PartialEq, Display, EnumString, Serialize, Deserialize)]
#[strum(serialize_all = "UPPERCASE")]
#[serde(rename_all = "UPPERCASE")]
pub enum StatusListType {
    BitstringStatusList,
    TokenStatusList,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationListEntry {
    pub id: RevocationListEntryId,
    pub entity_info: RevocationListEntityInfo,
    pub index: usize,
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
    Signature(String),
    WalletUnitAttestedKey(WalletUnitAttestedKeyId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RevocationListEntityInfo {
    Credential(CredentialId),
    Signature(String),
    WalletUnitAttestedKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UpdateRevocationListEntryId {
    Credential(CredentialId),
    Id(RevocationListEntryId),
    Index(RevocationListId, usize),
    Signature(String, RevocationListEntryId),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UpdateRevocationListEntryRequest {
    pub status: Option<RevocationListEntryStatus>,
}
