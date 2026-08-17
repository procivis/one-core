use proc_macros::Model;
use serde::{Deserialize, Serialize};
use shared_types::{DidId, DidMethodId, DidValue, KeyId, OrganisationId};
use strum::Display;
use time::OffsetDateTime;

use super::common::GetListResponse;
use super::key::Key;
use super::list_filter::{ListFilterValue, StringMatch};
use super::list_query::ListQuery;
use super::organisation::Organisation;
use super::relation::{Related, RelatedVec};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Display, Hash)]
#[strum(serialize_all = "camelCase")]
pub enum KeyRole {
    Authentication,
    AssertionMethod,
    KeyAgreement,
    CapabilityInvocation,
    CapabilityDelegation,
    UpdateKey,
}

#[derive(Clone, Debug)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct RelatedKey {
    pub role: KeyRole,
    pub key: Key,
    pub reference: String,
}

#[derive(Clone, Debug, Model)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct Did {
    #[model(id)]
    pub id: DidId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
    pub name: String,
    pub did: DidValue,
    pub did_type: DidType,
    pub did_method: DidMethodId,
    pub deactivated: bool,
    pub log: Option<String>,

    pub keys: RelatedVec<RelatedKey>,
    pub organisation: Related<Organisation>,
}

impl Did {
    pub fn is_remote(&self) -> bool {
        self.did_type.is_remote()
    }

    /// constructs full verification method identifier for the given key
    pub fn verification_method_id(&self, key: &RelatedKey) -> String {
        format!("{}#{}", self.did, key.reference)
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
pub enum ExactDidFilterColumn {
    Name,
    Did,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DidFilterValue {
    Name(StringMatch),
    Method(DidMethodId),
    Type(DidType),
    Did(StringMatch),
    OrganisationId(OrganisationId),
    Deactivated(bool),
    KeyAlgorithms(Vec<String>),
    KeyRoles(Vec<KeyRole>),
    KeyStorages(Vec<String>),
    KeyIds(Vec<KeyId>),
    DidMethods(Vec<DidMethodId>),
}

impl DidFilterValue {
    pub fn deactivated(v: impl Into<bool>) -> Self {
        Self::Deactivated(v.into())
    }
}

impl ListFilterValue for DidFilterValue {}

pub type GetDidList = GetListResponse<Did>;

pub type DidListQuery = ListQuery<SortableDidColumn, DidFilterValue>;

#[derive(Clone)]
pub struct UpdateDidRequest {
    pub id: DidId,
    pub deactivated: Option<bool>,
    pub log: Option<Option<String>>,
}
