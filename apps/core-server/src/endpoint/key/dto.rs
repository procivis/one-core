use dto_derive::Dto;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use one_core::service::key::dto::{KeyRequestDTO, KeyResponseDTO};

use crate::serialize::front_time;

#[derive(Clone, Debug, Deserialize, Dto, Serialize, ToSchema)]
#[dto(entity = "KeyRequestDTO")]
#[dto(request)]
#[serde(rename_all = "camelCase")]
pub struct KeyRequestRestDTO {
    pub organisation_id: Uuid,
    pub key_type: String,
    pub key_params: serde_json::Value,
    pub name: String,
    pub storage_type: String,
    pub storage_params: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize, Dto, Serialize, ToSchema)]
#[dto(entity = "KeyResponseDTO")]
#[dto(response)]
#[serde(rename_all = "camelCase")]
pub struct KeyResponseRestDTO {
    pub id: Uuid,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub organisation_id: Uuid,
    pub name: String,
    pub public_key: String,
    pub key_type: String,
    pub storage_type: String,
}
