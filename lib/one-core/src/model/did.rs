use time::OffsetDateTime;
use uuid::Uuid;

use super::{
    common::GetListResponse,
    key::{Key, KeyRelations},
    list_filter::{ListFilterValue, StringMatch},
    list_query::ListQuery,
    organisation::{Organisation, OrganisationId, OrganisationRelations},
};

pub type DidId = Uuid;
pub type DidValue = String;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DidType {
    Remote,
    Local,
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

    // Relations:
    pub keys: Option<Vec<RelatedKey>>,
    pub organisation: Option<Organisation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableDidColumn {
    Name,
    CreatedDate,
    Method,
    Type,
    Did,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DidFilterValue {
    Name(StringMatch),
    Method(String),
    Type(DidType),
    Did(StringMatch),
    OrganisationId(OrganisationId),
}

impl ListFilterValue for DidFilterValue {}

pub type GetDidList = GetListResponse<Did>;
pub type DidListQuery = ListQuery<SortableDidColumn, DidFilterValue>;

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct DidRelations {
    pub keys: Option<KeyRelations>,
    pub organisation: Option<OrganisationRelations>,
}
