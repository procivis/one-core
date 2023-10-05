use dto_derive::Dto;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use one_core::service::key::dto::KeyRequestDTO;

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
