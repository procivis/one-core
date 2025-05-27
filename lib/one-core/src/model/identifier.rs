use one_dto_mapper::Into;
use serde::{Deserialize, Serialize};
use shared_types::{IdentifierId, OrganisationId};
use strum::{AsRefStr, Display};
use time::OffsetDateTime;

use super::certificate::{Certificate, CertificateRelations};
use super::common::GetListResponse;
use super::did::{Did, DidRelations, KeyRole};
use super::key::{Key, KeyRelations};
use super::list_filter::{ListFilterValue, StringMatch};
use super::list_query::ListQuery;
use super::organisation::{Organisation, OrganisationRelations};
use crate::config;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Identifier {
    pub id: IdentifierId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub r#type: IdentifierType,
    pub is_remote: bool,
    pub state: IdentifierState,
    pub deleted_at: Option<OffsetDateTime>,

    // Relations:
    pub organisation: Option<Organisation>,
    pub did: Option<Did>,
    pub key: Option<Key>,
    pub certificates: Option<Vec<Certificate>>,
}

#[derive(Clone, Debug)]
pub enum SortableIdentifierColumn {
    Name,
    CreatedDate,
    Type,
    State,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Display, AsRefStr, Into)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[into(config::core_config::IdentifierType)]
pub enum IdentifierType {
    Key,
    Did,
    Certificate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdentifierState {
    Active,
    Deactivated,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct IdentifierRelations {
    pub organisation: Option<OrganisationRelations>,
    pub did: Option<DidRelations>,
    pub key: Option<KeyRelations>,
    pub certificates: Option<CertificateRelations>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UpdateIdentifierRequest {
    pub name: Option<String>,
    pub state: Option<IdentifierState>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentifierFilterValue {
    Ids(Vec<IdentifierId>),
    Name(StringMatch),
    Types(Vec<IdentifierType>),
    State(IdentifierState),
    OrganisationId(OrganisationId),
    DidMethods(Vec<String>),
    IsRemote(bool),
    KeyAlgorithms(Vec<String>),
    KeyRoles(Vec<KeyRole>),
    KeyStorages(Vec<String>),
}

impl ListFilterValue for IdentifierFilterValue {}

pub type GetIdentifierList = GetListResponse<Identifier>;

pub type IdentifierListQuery = ListQuery<SortableIdentifierColumn, IdentifierFilterValue>;
