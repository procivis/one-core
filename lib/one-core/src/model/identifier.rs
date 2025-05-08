use serde::{Deserialize, Serialize};
use shared_types::{IdentifierId, OrganisationId};
use time::OffsetDateTime;

use super::common::GetListResponse;
use super::did::{Did, DidRelations, KeyRole};
use super::key::{Key, KeyRelations};
use super::list_filter::{ListFilterValue, StringMatch};
use super::list_query::ListQuery;
use super::organisation::{Organisation, OrganisationRelations};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Identifier {
    pub id: IdentifierId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub r#type: IdentifierType,
    pub is_remote: bool,
    pub status: IdentifierStatus,
    pub deleted_at: Option<OffsetDateTime>,

    // Relations:
    pub organisation: Option<Organisation>,
    pub did: Option<Did>,
    pub key: Option<Key>,
}

#[derive(Clone, Debug)]
pub enum SortableIdentifierColumn {
    Name,
    CreatedDate,
    Type,
    Status,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdentifierType {
    Key,
    Did,
    Certificate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdentifierStatus {
    Active,
    Deactivated,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct IdentifierRelations {
    pub organisation: Option<OrganisationRelations>,
    pub did: Option<DidRelations>,
    pub key: Option<KeyRelations>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UpdateIdentifierRequest {
    pub name: Option<String>,
    pub status: Option<IdentifierStatus>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentifierFilterValue {
    Ids(Vec<IdentifierId>),
    Name(StringMatch),
    Type(IdentifierType),
    Status(IdentifierStatus),
    OrganisationId(OrganisationId),
    KeyAlgorithms(Vec<String>),
    KeyRoles(Vec<KeyRole>),
    KeyStorages(Vec<String>),
}

impl ListFilterValue for IdentifierFilterValue {}

pub type GetIdentifierList = GetListResponse<Identifier>;

pub type IdentifierListQuery = ListQuery<SortableIdentifierColumn, IdentifierFilterValue>;
