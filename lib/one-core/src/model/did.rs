use serde::Deserialize;
use shared_types::{DidId, DidValue};
use time::OffsetDateTime;

use super::{
    common::GetListResponse,
    key::{Key, KeyRelations},
    list_filter::{ListFilterValue, StringMatch},
    list_query::ListQuery,
    organisation::{Organisation, OrganisationId, OrganisationRelations},
};

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DidType {
    Remote,
    Local,
}

impl DidType {
    pub fn is_remote(&self) -> bool {
        matches!(self, Self::Remote)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyRole {
    Authentication,
    AssertionMethod,
    KeyAgreement,
    CapabilityInvocation,
    CapabilityDelegation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelatedKey {
    pub role: KeyRole,
    pub key: Key,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Did {
    pub id: DidId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub did: DidValue,
    pub did_type: DidType,
    pub did_method: String,
    pub deactivated: bool,

    // Relations:
    pub keys: Option<Vec<RelatedKey>>,
    pub organisation: Option<Organisation>,
}

impl Did {
    pub fn is_remote(&self) -> bool {
        self.did_type.is_remote()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableDidColumn {
    Name,
    CreatedDate,
    Method,
    Type,
    Did,
    Deactivated,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DidFilterValue {
    Name(StringMatch),
    Method(String),
    Type(DidType),
    Did(StringMatch),
    OrganisationId(OrganisationId),
    Deactivated(bool),
    KeyAlgorithms(Vec<String>),
    KeyRoles(Vec<KeyRole>),
}

impl DidFilterValue {
    pub fn deactivated(v: impl Into<bool>) -> Self {
        Self::Deactivated(v.into())
    }
}

impl ListFilterValue for DidFilterValue {}

pub type GetDidList = GetListResponse<Did>;
pub type DidListQuery = ListQuery<SortableDidColumn, DidFilterValue>;

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct DidRelations {
    pub keys: Option<KeyRelations>,
    pub organisation: Option<OrganisationRelations>,
}

pub struct UpdateDidRequest {
    pub id: DidId,
    pub deactivated: Option<bool>,
}
