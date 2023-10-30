use dto_mapper::From;
use one_core::common_mapper::vector_into;
use one_core::service::proof_schema::dto::{
    CreateProofSchemaClaimRequestDTO, CreateProofSchemaRequestDTO, GetProofSchemaListItemDTO,
    GetProofSchemaResponseDTO, ProofClaimSchemaResponseDTO,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

use crate::{
    dto::common::GetListQueryParams,
    endpoint::credential_schema::dto::CredentialSchemaListItemResponseRestDTO,
    serialize::front_time,
};

// create endpoint
#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema, Validate, From)]
#[convert(into = "CreateProofSchemaRequestDTO")]
#[serde(rename_all = "camelCase")]
pub struct CreateProofSchemaRequestRestDTO {
    #[validate(length(min = 1))]
    pub name: String,
    pub organisation_id: Uuid,
    pub expire_duration: u32,
    #[convert(with_fn = "vector_into")]
    #[validate(length(min = 1))]
    pub claim_schemas: Vec<ClaimProofSchemaRequestRestDTO>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[convert(into = "CreateProofSchemaClaimRequestDTO")]
pub struct ClaimProofSchemaRequestRestDTO {
    pub id: Uuid,
    pub required: bool,
}

// list endpoint
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[convert(into = "one_core::model::proof_schema::SortableProofSchemaColumn")]
pub enum SortableProofSchemaColumnRestEnum {
    Name,
    CreatedDate,
}

pub type GetProofSchemaQuery = GetListQueryParams<SortableProofSchemaColumnRestEnum>;

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[convert(from = "GetProofSchemaListItemDTO")]
pub struct GetProofSchemaListItemResponseRestDTO {
    pub id: Uuid,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub expire_duration: u32,
}

// detail endpoint
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[convert(from = "GetProofSchemaResponseDTO")]
#[serde(rename_all = "camelCase")]
pub struct GetProofSchemaResponseRestDTO {
    pub id: Uuid,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub expire_duration: u32,
    pub organisation_id: Uuid,
    #[convert(with_fn = "vector_into")]
    pub claim_schemas: Vec<ProofClaimSchemaResponseRestDTO>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[convert(from = "ProofClaimSchemaResponseDTO")]
pub struct ProofClaimSchemaResponseRestDTO {
    pub id: Uuid,
    pub required: bool,
    pub key: String,
    #[schema(example = "STRING")]
    pub data_type: String,
    pub credential_schema: CredentialSchemaListItemResponseRestDTO,
}
