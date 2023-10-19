use dto_derive::Dto;
use one_core::service::did::dto::CreateDidRequestKeysDTO;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    dto::common::GetListQueryParams, endpoint::key::dto::KeyListItemResponseRestDTO,
    serialize::front_time,
};

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DidType {
    #[default]
    Remote,
    Local,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DidListItemResponseRestDTO {
    pub id: Uuid,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub did: String,
    #[serde(rename = "type")]
    pub did_type: DidType,
    #[serde(rename = "method")]
    pub did_method: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DidResponseRestDTO {
    pub id: Uuid,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub organisation_id: Uuid,
    pub did: String,
    #[serde(rename = "type")]
    pub did_type: DidType,
    #[serde(rename = "method")]
    pub did_method: String,
    pub keys: DidResponseKeysRestDTO,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DidResponseKeysRestDTO {
    pub authentication: Vec<KeyListItemResponseRestDTO>,
    pub assertion: Vec<KeyListItemResponseRestDTO>,
    pub key_agreement: Vec<KeyListItemResponseRestDTO>,
    pub capability_invocation: Vec<KeyListItemResponseRestDTO>,
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

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, Dto)]
#[dto(entity = "CreateDidRequestKeysDTO")]
#[dto(request)]
#[serde(rename_all = "camelCase")]
pub struct CreateDidRequestKeysRestDTO {
    pub authentication: Vec<Uuid>,
    pub assertion: Vec<Uuid>,
    pub key_agreement: Vec<Uuid>,
    pub capability_invocation: Vec<Uuid>,
    pub capability_delegation: Vec<Uuid>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum SortableDidColumnRestDTO {
    Name,
    CreatedDate,
    Method,
    Type,
    Did,
}

pub type GetDidQuery = GetListQueryParams<SortableDidColumnRestDTO>;
