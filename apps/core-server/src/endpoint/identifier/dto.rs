use one_core::model::identifier::{IdentifierStatus, IdentifierType, SortableIdentifierColumn};
use one_core::service::identifier::dto::{
    CreateIdentifierDidRequestDTO, CreateIdentifierRequestDTO, GetIdentifierListItemResponseDTO,
    GetIdentifierListResponseDTO, GetIdentifierResponseDTO,
};
use one_dto_mapper::{From, Into, TryFrom, convert_inner, try_convert_inner};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use shared_types::{IdentifierId, KeyId, OrganisationId};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

use crate::dto::common::ListQueryParamsRest;
use crate::endpoint::did::dto::{CreateDidRequestKeysRestDTO, DidResponseRestDTO, KeyRoleRestEnum};
use crate::endpoint::key::dto::KeyResponseRestDTO;
use crate::mapper::MapperError;
use crate::serialize::front_time;

#[skip_serializing_none]
#[derive(Debug, Deserialize, ToSchema, Validate, Into)]
#[serde(rename_all = "camelCase")]
#[into(CreateIdentifierRequestDTO)]
pub struct CreateIdentifierRequestRestDTO {
    pub name: String,
    #[into(with_fn = "convert_inner")]
    pub did: Option<CreateIdentifierDidRequestRestDTO>,
    pub key_id: Option<KeyId>,
    pub organisation_id: OrganisationId,
}

#[skip_serializing_none]
#[derive(Debug, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(CreateIdentifierDidRequestDTO)]
pub struct CreateIdentifierDidRequestRestDTO {
    pub name: Option<String>,
    pub method: String,
    pub keys: CreateDidRequestKeysRestDTO,
    pub params: Option<serde_json::Value>,
}

#[skip_serializing_none]
#[derive(Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(GetIdentifierListItemResponseDTO)]
pub struct GetIdentifierListItemResponseRestDTO {
    pub id: IdentifierId,
    pub name: String,
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub created_date: OffsetDateTime,
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub last_modified: OffsetDateTime,
    #[from(rename = "status")]
    pub state: IdentifierStatusRest,
    pub r#type: IdentifierTypeRest,
    pub is_remote: bool,
    pub organisation_id: Option<OrganisationId>,
}

#[skip_serializing_none]
#[derive(Debug, Serialize, ToSchema, TryFrom)]
#[serde(rename_all = "camelCase")]
#[try_from(T = GetIdentifierResponseDTO, Error = MapperError)]
pub struct GetIdentifierResponseRestDTO {
    #[try_from(infallible)]
    pub id: IdentifierId,
    #[try_from(infallible)]
    pub name: String,
    #[try_from(infallible)]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub created_date: OffsetDateTime,
    #[try_from(infallible)]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub last_modified: OffsetDateTime,
    #[try_from(with_fn = "try_convert_inner")]
    pub did: Option<DidResponseRestDTO>,
    #[try_from(with_fn = "try_convert_inner")]
    pub key: Option<KeyResponseRestDTO>,
    #[try_from(infallible, with_fn = "convert_inner")]
    pub organisation_id: Option<OrganisationId>,
    #[try_from(infallible, rename = "status")]
    pub state: IdentifierStatusRest,
    #[try_from(infallible)]
    pub r#type: IdentifierTypeRest,
    #[try_from(infallible)]
    pub is_remote: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, From, Into)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[from(IdentifierStatus)]
#[into(IdentifierStatus)]
pub enum IdentifierStatusRest {
    Active,
    Deactivated,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, From, Into)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[from(IdentifierType)]
#[into(IdentifierType)]
pub enum IdentifierTypeRest {
    Did,
    Key,
    Certificate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, From, Into)]
#[serde(rename_all = "camelCase")]
#[from(SortableIdentifierColumn)]
#[into(SortableIdentifierColumn)]
pub enum SortableIdentifierColumnRest {
    Name,
    CreatedDate,
    Type,
    Status,
}

#[derive(Clone, Debug, Deserialize, ToSchema, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct IdentifierFilterQueryParamsRestDTO {
    #[param(rename = "ids[]", nullable = false)]
    pub ids: Option<Vec<IdentifierId>>,
    #[param(nullable = false)]
    pub name: Option<String>,
    #[param(nullable = false)]
    pub r#type: Option<IdentifierTypeRest>,
    #[param(nullable = false)]
    pub state: Option<IdentifierStatusRest>,
    #[param(rename = "didMethods[]", nullable = false)]
    pub did_methods: Option<Vec<String>>,
    #[param(nullable = false)]
    #[serde(default, deserialize_with = "deserialize_bool_from_string")]
    pub is_remote: Option<bool>,
    #[param(rename = "keyAlgorithms[]", nullable = false)]
    pub key_algorithms: Option<Vec<String>>,
    #[param(rename = "keyRoles[]", inline, nullable = false)]
    pub key_roles: Option<Vec<KeyRoleRestEnum>>,
    #[param(rename = "keyStorages[]", nullable = false)]
    pub key_storages: Option<Vec<String>>,

    #[param(rename = "exact[]", inline, nullable = false)]
    pub exact: Option<Vec<ExactIdentifierFilterColumnRestEnum>>,
    pub organisation_id: OrganisationId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum ExactIdentifierFilterColumnRestEnum {
    Name,
}

pub type GetIdentifierQuery =
    ListQueryParamsRest<IdentifierFilterQueryParamsRestDTO, SortableIdentifierColumnRest>;

#[skip_serializing_none]
#[derive(Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(GetIdentifierListResponseDTO)]
pub struct GetIdentifierListResponseRestDTO {
    pub total_pages: u64,
    pub total_items: u64,
    #[from(with_fn = "convert_inner")]
    pub values: Vec<GetIdentifierListItemResponseRestDTO>,
}

fn deserialize_bool_from_string<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: Option<String> = Option::deserialize(deserializer)?;
    match s {
        Some(s) => match s.to_lowercase().as_str() {
            "true" => Ok(Some(true)),
            "false" => Ok(Some(false)),
            _ => Err(serde::de::Error::custom("invalid boolean value")),
        },
        None => Ok(None),
    }
}
