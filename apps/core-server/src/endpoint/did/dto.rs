use dto_mapper::{convert_inner, try_convert_inner, From, Into, TryFrom};
use one_core::service::did::dto::{
    CreateDidRequestKeysDTO, DidListItemResponseDTO, DidPatchRequestDTO, DidResponseDTO,
    DidResponseKeysDTO,
};
use serde::{Deserialize, Serialize};
use shared_types::{DidId, DidValue, KeyId, OrganisationId};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::dto::common::ListQueryParamsRest;
use crate::endpoint::key::dto::KeyListItemResponseRestDTO;
use crate::mapper::MapperError;
use crate::serialize::front_time;

pub type GetDidQuery = ListQueryParamsRest<DidFilterQueryParamsRest, SortableDidColumnRestDTO>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, Into, From)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[from("one_core::model::did::DidType")]
#[into("one_core::model::did::DidType")]
pub enum DidType {
    Remote,
    Local,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(DidListItemResponseDTO)]
pub struct DidListItemResponseRestDTO {
    pub id: DidId,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub did: DidValue,
    #[serde(rename = "type")]
    pub did_type: DidType,
    #[serde(rename = "method")]
    pub did_method: String,
    pub deactivated: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, TryFrom)]
#[try_from(T = DidResponseDTO, Error = MapperError)]
#[serde(rename_all = "camelCase")]
pub struct DidResponseRestDTO {
    #[try_from(infallible)]
    pub id: DidId,
    #[try_from(infallible)]
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[try_from(infallible)]
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    #[try_from(infallible)]
    pub name: String,
    #[try_from(infallible)]
    pub organisation_id: Uuid,
    #[try_from(infallible)]
    pub did: DidValue,
    #[try_from(infallible)]
    #[serde(rename = "type")]
    pub did_type: DidType,
    #[try_from(infallible)]
    #[serde(rename = "method")]
    pub did_method: String,
    pub keys: DidResponseKeysRestDTO,
    #[try_from(infallible)]
    pub deactivated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, TryFrom)]
#[try_from(T = DidResponseKeysDTO, Error = MapperError)]
#[serde(rename_all = "camelCase")]
pub struct DidResponseKeysRestDTO {
    #[try_from(with_fn = try_convert_inner)]
    pub authentication: Vec<KeyListItemResponseRestDTO>,
    #[try_from(with_fn = try_convert_inner)]
    pub assertion_method: Vec<KeyListItemResponseRestDTO>,
    #[try_from(with_fn = try_convert_inner)]
    pub key_agreement: Vec<KeyListItemResponseRestDTO>,
    #[try_from(with_fn = try_convert_inner)]
    pub capability_invocation: Vec<KeyListItemResponseRestDTO>,
    #[try_from(with_fn = try_convert_inner)]
    pub capability_delegation: Vec<KeyListItemResponseRestDTO>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateDidRequestRestDTO {
    pub name: String,
    pub organisation_id: OrganisationId,
    pub method: String,
    pub keys: CreateDidRequestKeysRestDTO,
    #[schema(value_type = Object)]
    pub params: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, Into)]
#[into(CreateDidRequestKeysDTO)]
#[serde(rename_all = "camelCase")]
pub struct CreateDidRequestKeysRestDTO {
    #[into(with_fn = convert_inner)]
    pub authentication: Vec<KeyId>,
    #[into(with_fn = convert_inner)]
    pub assertion_method: Vec<KeyId>,
    #[into(with_fn = convert_inner)]
    pub key_agreement: Vec<KeyId>,
    #[into(with_fn = convert_inner)]
    pub capability_invocation: Vec<KeyId>,
    #[into(with_fn = convert_inner)]
    pub capability_delegation: Vec<KeyId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into("one_core::model::did::SortableDidColumn")]
pub enum SortableDidColumnRestDTO {
    Name,
    CreatedDate,
    Method,
    Type,
    Did,
    Deactivated,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum ExactDidFilterColumnRestEnum {
    Name,
    Did,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, Into)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[into("one_core::model::did::KeyRole")]
pub enum KeyRoleRestEnum {
    Authentication,
    AssertionMethod,
    KeyAgreement,
    CapabilityInvocation,
    CapabilityDelegation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum Boolean {
    True,
    False,
}

impl From<Boolean> for bool {
    fn from(boolean: Boolean) -> Self {
        matches!(boolean, Boolean::True)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct DidFilterQueryParamsRest {
    pub name: Option<String>,
    pub did: Option<String>,
    #[param(inline)]
    pub r#type: Option<DidType>,
    #[param(inline, rename = "exact[]")]
    pub exact: Option<Vec<ExactDidFilterColumnRestEnum>>,
    pub organisation_id: OrganisationId,
    #[param(inline)]
    pub deactivated: Option<Boolean>,
    #[param(inline, rename = "keyAlgorithms[]")]
    pub key_algorithms: Option<Vec<String>>,
    #[param(inline, rename = "keyRoles[]")]
    pub key_roles: Option<Vec<KeyRoleRestEnum>>,
    #[param(inline, rename = "keyStorages[]")]
    pub key_storages: Option<Vec<String>>,
    #[param(inline, rename = "didMethods[]")]
    pub did_methods: Option<Vec<String>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(DidPatchRequestDTO)]
pub struct DidPatchRequestRestDTO {
    pub deactivated: Option<bool>,
}
