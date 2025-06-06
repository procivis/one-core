use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::identifier::{Identifier, IdentifierRelations};

pub type RevocationListId = Uuid;

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

#[derive(Clone, Debug, Eq, PartialEq, Display, Serialize)]
pub enum RevocationListPurpose {
    Revocation,
    Suspension,
}

#[derive(Clone, Debug, Eq, PartialEq, Display, Serialize, Deserialize)]
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
