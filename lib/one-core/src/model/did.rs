use dto_mapper::{convert_inner_of_inner, From, Into};
use one_providers::common_models::key::Key;
use serde::{Deserialize, Serialize};
use shared_types::{DidId, DidValue, KeyId, OrganisationId};
use time::OffsetDateTime;

use super::common::GetListResponse;
use super::list_filter::{ListFilterValue, StringMatch};
use super::list_query::ListQuery;
use super::organisation::{Organisation, OrganisationRelations};
use crate::model::key::KeyRelations;
use crate::service::error::{ServiceError, ValidationError};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Into, From)]
#[into(one_providers::common_models::did::DidType)]
#[from(one_providers::common_models::did::DidType)]
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

#[derive(Clone, Debug, Eq, PartialEq, Into, From)]
#[into(one_providers::common_models::did::KeyRole)]
#[from(one_providers::common_models::did::KeyRole)]
pub enum KeyRole {
    Authentication,
    AssertionMethod,
    KeyAgreement,
    CapabilityInvocation,
    CapabilityDelegation,
}

#[derive(Clone, Debug, Eq, PartialEq, Into, From)]
#[into(one_providers::common_models::did::RelatedKey)]
#[from(one_providers::common_models::did::RelatedKey)]
pub struct RelatedKey {
    pub role: KeyRole,
    pub key: Key,
}

#[derive(Clone, Debug, Eq, PartialEq, Into, From)]
#[into(one_providers::common_models::did::Did)]
#[from(one_providers::common_models::did::Did)]
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
    #[into(with_fn = "convert_inner_of_inner")]
    #[from(with_fn = "convert_inner_of_inner")]
    pub keys: Option<Vec<RelatedKey>>,
    #[into(skip)]
    #[from(replace = None)]
    pub organisation: Option<Organisation>,
}

impl Did {
    pub fn is_remote(&self) -> bool {
        self.did_type.is_remote()
    }

    pub fn find_key(&self, key_id: &KeyId, role: KeyRole) -> Result<&Key, ServiceError> {
        let key_id: one_providers::common_models::key::KeyId = key_id.to_owned().into();

        let mut same_id_keys = self
            .keys
            .as_ref()
            .ok_or_else(|| ServiceError::MappingError("keys is None".to_string()))?
            .iter()
            .filter(|entry| entry.key.id == key_id)
            .peekable();

        if same_id_keys.peek().is_none() {
            return Err(ValidationError::KeyNotFound.into());
        }

        Ok(&same_id_keys
            .find(|entry| entry.role == role)
            .ok_or_else(|| ValidationError::InvalidKey("key has wrong role".into()))?
            .key)
    }

    pub fn find_first_key_by_role(&self, role: KeyRole) -> Result<&Key, ServiceError> {
        Ok(&self
            .keys
            .as_ref()
            .ok_or_else(|| ServiceError::MappingError("keys is None".to_string()))?
            .iter()
            .find(|entry| entry.role == role)
            .ok_or_else(|| ValidationError::InvalidKey("no matching keys found".into()))?
            .key)
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
    DidMethods(Vec<String>),
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
