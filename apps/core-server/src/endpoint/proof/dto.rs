use crate::{
    dto::common::GetListQueryParams,
    proof_schema::dto::{GetProofSchemaListItemResponseRestDTO, ProofClaimSchemaResponseRestDTO},
    serialize::{front_time, front_time_option},
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProofStateRestEnum {
    Created,
    Pending,
    Offered,
    Accepted,
    Rejected,
    Error,
}

// create endpoint
#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateProofRequestRestDTO {
    pub proof_schema_id: Uuid,
    #[schema(example = "<uuid; did identifier>")]
    pub verifier_did: Uuid,
    pub transport: String,
}

// list endpoint
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum SortableProofColumnRestEnum {
    #[serde(rename = "schema.name")]
    ProofSchemaName,
    VerifierDid,
    CreatedDate,
    State,
}

pub type GetProofQuery = GetListQueryParams<SortableProofColumnRestEnum>;

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProofListItemResponseRestDTO {
    pub id: Uuid,

    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,

    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,

    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub issuance_date: OffsetDateTime,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "front_time_option")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub requested_date: Option<OffsetDateTime>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "front_time_option")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub completed_date: Option<OffsetDateTime>,

    pub verifier_did: String,
    pub transport: String,
    pub state: ProofStateRestEnum,
    pub schema: Option<GetProofSchemaListItemResponseRestDTO>,
}

// detail endpoint
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProofDetailResponseRestDTO {
    pub id: Uuid,

    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,

    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,

    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub issuance_date: OffsetDateTime,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "front_time_option")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub requested_date: Option<OffsetDateTime>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "front_time_option")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub completed_date: Option<OffsetDateTime>,

    pub verifier_did: String,
    pub transport: String,
    pub state: ProofStateRestEnum,
    pub organisation_id: Uuid,
    pub schema: Option<GetProofSchemaListItemResponseRestDTO>,
    pub claims: Vec<ProofClaimRestDTO>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProofClaimRestDTO {
    pub schema: ProofClaimSchemaResponseRestDTO,
    pub value: Option<String>,
}
