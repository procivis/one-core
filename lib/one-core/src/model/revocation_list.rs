use serde::{Deserialize, Serialize};
use shared_types::{CredentialId, RevocationListId, WalletUnitAttestedKeyId};
use strum::{Display, EnumString};
use time::OffsetDateTime;

use crate::model::credential::CredentialStateEnum;
use crate::model::identifier::{Identifier, IdentifierRelations};
use crate::model::wallet_unit::WalletUnitStatus;

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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RevocationListEntityId {
    Credential(CredentialId),
    WalletUnitAttestedKey(WalletUnitAttestedKeyId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RevocationListEntityInfo {
    Credential(CredentialId, CredentialStateEnum),
    WalletUnitAttestedKey(WalletUnitAttestedKeyId, WalletUnitStatus),
}

impl From<RevocationListEntityInfo> for RevocationListEntityId {
    fn from(value: RevocationListEntityInfo) -> Self {
        match value {
            RevocationListEntityInfo::Credential(id, _) => Self::Credential(id),
            RevocationListEntityInfo::WalletUnitAttestedKey(id, _) => {
                Self::WalletUnitAttestedKey(id)
            }
        }
    }
}
