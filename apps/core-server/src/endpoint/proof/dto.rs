use crate::endpoint::credential::dto::GetCredentialResponseRestDTO;
use crate::{
    dto::common::GetListQueryParams,
    endpoint::proof_schema::dto::{
        GetProofSchemaListItemResponseRestDTO, ProofClaimSchemaResponseRestDTO,
    },
    serialize::{front_time, front_time_option},
};
use dto_mapper::From;
use one_core::common_mapper::vector_into;
use one_core::model::proof::ProofStateEnum;
use one_core::service::proof::dto::{
    PresentationDefinitionFieldDTO, PresentationDefinitionRequestGroupResponseDTO,
    PresentationDefinitionRequestedCredentialResponseDTO, PresentationDefinitionResponseDTO,
    PresentationDefinitionRuleDTO, PresentationDefinitionRuleTypeEnum, ProofClaimDTO,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, From)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[convert(from = "ProofStateEnum")]
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

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[convert(from = "PresentationDefinitionResponseDTO")]
#[serde(rename_all = "camelCase")]
pub struct PresentationDefinitionResponseRestDTO {
    #[convert(with_fn = "vector_into")]
    pub request_groups: Vec<PresentationDefinitionRequestGroupResponseRestDTO>,
    #[convert(with_fn = "vector_into")]
    pub credentials: Vec<GetCredentialResponseRestDTO>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[convert(from = "PresentationDefinitionRequestGroupResponseDTO")]
#[serde(rename_all = "camelCase")]
pub struct PresentationDefinitionRequestGroupResponseRestDTO {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    pub rule: PresentationDefinitionRuleRestDTO,
    #[convert(with_fn = "vector_into")]
    pub requested_credentials: Vec<PresentationDefinitionRequestedCredentialResponseRestDTO>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[convert(from = "PresentationDefinitionRequestedCredentialResponseDTO")]
#[serde(rename_all = "camelCase")]
pub struct PresentationDefinitionRequestedCredentialResponseRestDTO {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    #[convert(with_fn = "vector_into")]
    pub fields: Vec<PresentationDefinitionFieldRestDTO>,
    #[convert(with_fn = "vector_into")]
    pub applicable_credentials: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[convert(from = "PresentationDefinitionFieldDTO")]
pub struct PresentationDefinitionFieldRestDTO {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    pub required: Option<bool>,
    pub key_map: HashMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, From)]
#[convert(from = "PresentationDefinitionRuleTypeEnum")]
pub enum PresentationDefinitionRuleTypeRestEnum {
    #[serde(rename = "all")]
    All,
    #[serde(rename = "pick")]
    Pick,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[convert(from = "PresentationDefinitionRuleDTO")]
pub struct PresentationDefinitionRuleRestDTO {
    //#[serde(serialize_with = "type")]
    pub r#type: PresentationDefinitionRuleTypeRestEnum,
    pub min: Option<u32>,
    pub max: Option<u32>,
    pub count: Option<u32>,
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

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[convert(from = "ProofClaimDTO")]
pub struct ProofClaimRestDTO {
    pub schema: ProofClaimSchemaResponseRestDTO,
    pub value: Option<String>,
}
