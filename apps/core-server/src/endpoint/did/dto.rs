use crate::{
    dto::common::ListQueryParamsRest, endpoint::key::dto::KeyListItemResponseRestDTO,
    mapper::MapperError, serialize::front_time,
};
use dto_mapper::iterable_try_into;
use dto_mapper::{From, Into, TryFrom};
use one_core::service::did::dto::{
    CreateDidRequestKeysDTO, DidListItemResponseDTO, DidPatchRequestDTO, DidResponseDTO,
    DidResponseKeysDTO,
};
use serde::{Deserialize, Serialize};
use shared_types::{DidId, DidValue};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

pub type GetDidQuery = ListQueryParamsRest<DidFilterQueryParamsRest, SortableDidColumnRestDTO>;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize, ToSchema, Into, From)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[from("one_core::model::did::DidType")]
#[into("one_core::model::did::DidType")]
pub enum DidType {
    #[default]
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
    #[try_from(with_fn = iterable_try_into)]
    pub authentication: Vec<KeyListItemResponseRestDTO>,
    #[try_from(with_fn = iterable_try_into)]
    pub assertion: Vec<KeyListItemResponseRestDTO>,
    #[try_from(with_fn = iterable_try_into)]
    pub key_agreement: Vec<KeyListItemResponseRestDTO>,
    #[try_from(with_fn = iterable_try_into)]
    pub capability_invocation: Vec<KeyListItemResponseRestDTO>,
    #[try_from(with_fn = iterable_try_into)]
    pub capability_delegation: Vec<KeyListItemResponseRestDTO>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateDidRequestRestDTO {
    pub name: String,
    pub organisation_id: Uuid,
    pub method: String,
    pub keys: CreateDidRequestKeysRestDTO,
    #[schema(value_type = Object)]
    pub params: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, Into)]
#[into(CreateDidRequestKeysDTO)]
#[serde(rename_all = "camelCase")]
pub struct CreateDidRequestKeysRestDTO {
    pub authentication: Vec<Uuid>,
    pub assertion: Vec<Uuid>,
    pub key_agreement: Vec<Uuid>,
    pub capability_invocation: Vec<Uuid>,
    pub capability_delegation: Vec<Uuid>,
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
    pub organisation_id: Uuid,
    #[param(inline)]
    pub deactivated: Option<Boolean>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(DidPatchRequestDTO)]
pub struct DidPatchRequestRestDTO {
    pub deactivated: Option<bool>,
}
