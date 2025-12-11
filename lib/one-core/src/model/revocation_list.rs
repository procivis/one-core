use serde::{Deserialize, Serialize};
use shared_types::{CredentialId, RevocationListId, WalletUnitAttestedKeyId};
use strum::{Display, EnumString};
use time::OffsetDateTime;
use uuid::Uuid;

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
    WalletUnitAttestedKey(WalletUnitAttestedKeyId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RevocationListEntityInfo {
    Credential(CredentialId),
    WalletUnitAttestedKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UpdateRevocationListEntryId {
    Credential(CredentialId),
    Id(Uuid),
    Index(RevocationListId, usize),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UpdateRevocationListEntryRequest {
    pub status: Option<RevocationListEntryStatus>,
}
