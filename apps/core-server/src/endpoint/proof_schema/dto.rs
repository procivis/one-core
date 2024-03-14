use dto_mapper::convert_inner;
use dto_mapper::{From, Into};
use one_core::model::credential_schema::CredentialSchemaId;
use one_core::service::proof_schema::dto::{
    CreateProofSchemaClaimRequestDTO, CreateProofSchemaRequestDTO, GetProofSchemaListItemDTO,
    GetProofSchemaResponseDTO, ProofClaimSchemaResponseDTO, ProofInputSchemaRequestDTO,
    ProofInputSchemaResponseDTO,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

use crate::{
    dto::common::GetListQueryParams,
    endpoint::credential_schema::dto::CredentialSchemaListItemResponseRestDTO,
    serialize::{front_time, front_time_option},
};

// create endpoint
#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema, Validate, Into)]
#[into(CreateProofSchemaRequestDTO)]
#[serde(rename_all = "camelCase")]
pub struct CreateProofSchemaRequestRestDTO {
    #[validate(length(min = 1))]
    #[schema(min_length = 1)]
    pub name: String,
    pub organisation_id: Uuid,
    pub expire_duration: u32,
    #[into(with_fn = convert_inner)]
    #[schema(min_items = 1)]
    pub proof_input_schemas: Vec<ProofInputSchemaRequestRestDTO>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema, Validate, Into)]
#[into(ProofInputSchemaRequestDTO)]
#[serde(rename_all = "camelCase")]
pub struct ProofInputSchemaRequestRestDTO {
    pub credential_schema_id: CredentialSchemaId,
    pub validity_constraint: Option<i64>,
    #[into(with_fn = convert_inner)]
    #[schema(min_items = 1)]
    pub claim_schemas: Vec<ClaimProofSchemaRequestRestDTO>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(CreateProofSchemaClaimRequestDTO)]
pub struct ClaimProofSchemaRequestRestDTO {
    pub id: Uuid,
    pub required: bool,
}

// list endpoint
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into("one_core::model::proof_schema::SortableProofSchemaColumn")]
pub enum SortableProofSchemaColumnRestEnum {
    Name,
    CreatedDate,
}

pub type GetProofSchemaQuery = GetListQueryParams<SortableProofSchemaColumnRestEnum>;

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(GetProofSchemaListItemDTO)]
pub struct GetProofSchemaListItemResponseRestDTO {
    pub id: Uuid,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(
        serialize_with = "front_time_option",
        skip_serializing_if = "Option::is_none"
    )]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub deleted_at: Option<OffsetDateTime>,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub expire_duration: u32,
    pub validity_constraint: Option<i64>,
}

// detail endpoint
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[from(GetProofSchemaResponseDTO)]
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
    #[from(with_fn = convert_inner)]
    pub proof_input_schemas: Vec<ProofInputSchemaResponseRestDTO>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(ProofClaimSchemaResponseDTO)]
pub struct ProofClaimSchemaResponseRestDTO {
    pub id: Uuid,
    pub required: bool,
    pub key: String,
    #[schema(example = "STRING")]
    pub data_type: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(ProofInputSchemaResponseDTO)]
pub struct ProofInputSchemaResponseRestDTO {
    #[from(with_fn = convert_inner)]
    pub claim_schemas: Vec<ProofClaimSchemaResponseRestDTO>,
    pub credential_schema: CredentialSchemaListItemResponseRestDTO,
    pub validity_constraint: Option<i64>,
}
