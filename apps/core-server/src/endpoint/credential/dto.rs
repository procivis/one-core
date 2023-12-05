use crate::endpoint::did::dto::DidListItemResponseRestDTO;
use crate::serialize::front_time;
use crate::serialize::front_time_option;
use crate::{
    dto::common::GetListQueryParams,
    endpoint::credential_schema::dto::{
        CredentialClaimSchemaResponseRestDTO, CredentialSchemaListItemResponseRestDTO,
    },
};
use dto_mapper::From;
use one_core::common_mapper::convert_inner;
use one_core::service::credential::dto::CreateCredentialRequestDTO;
use one_core::service::credential::dto::CredentialDetailResponseDTO;
use one_core::service::credential::dto::CredentialListItemResponseDTO;
use one_core::service::credential::dto::CredentialRequestClaimDTO;
use one_core::service::credential::dto::CredentialRevocationCheckResponseDTO;
use one_core::service::credential::dto::CredentialStateEnum;
use one_core::service::credential::dto::DetailCredentialClaimResponseDTO;
use one_core::service::credential::dto::DetailCredentialSchemaResponseDTO;
use serde::{Deserialize, Serialize};
use shared_types::DidValue;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[convert(from = "CredentialListItemResponseDTO")]
pub struct CredentialListItemResponseRestDTO {
    pub id: Uuid,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub issuance_date: OffsetDateTime,
    #[serde(serialize_with = "front_time_option")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub revocation_date: Option<OffsetDateTime>,
    pub state: CredentialStateRestEnum,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub schema: CredentialSchemaListItemResponseRestDTO,
    pub issuer_did: Option<DidValue>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[convert(from = "CredentialDetailResponseDTO")]
#[serde(rename_all = "camelCase")]
pub struct GetCredentialResponseRestDTO {
    pub id: Uuid,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub issuance_date: OffsetDateTime,
    #[serde(serialize_with = "front_time_option")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub revocation_date: Option<OffsetDateTime>,
    pub state: CredentialStateRestEnum,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub schema: CredentialDetailSchemaResponseRestDTO,
    #[convert(with_fn = convert_inner)]
    pub issuer_did: Option<DidListItemResponseRestDTO>,
    #[convert(with_fn = convert_inner)]
    pub claims: Vec<CredentialDetailClaimResponseRestDTO>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[convert(from = "DetailCredentialSchemaResponseDTO")]
pub struct CredentialDetailSchemaResponseRestDTO {
    pub id: Uuid,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: String,
    pub revocation_method: String,
    pub organisation_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[convert(from = "DetailCredentialClaimResponseDTO")]
pub struct CredentialDetailClaimResponseRestDTO {
    pub schema: CredentialClaimSchemaResponseRestDTO,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, From)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[convert(from = "CredentialStateEnum")]
pub enum CredentialStateRestEnum {
    Created,
    Pending,
    Offered,
    Accepted,
    Rejected,
    Revoked,
    Error,
}

pub type GetCredentialQuery = GetListQueryParams<SortableCredentialColumnRestEnum>;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[convert(into = "one_core::model::credential::SortableCredentialColumn")]
pub enum SortableCredentialColumnRestEnum {
    CreatedDate,
    #[serde(rename = "schema.name")]
    SchemaName,
    IssuerDid,
    State,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[convert(into = "CreateCredentialRequestDTO")]
#[serde(rename_all = "camelCase")]
pub struct CreateCredentialRequestRestDTO {
    pub credential_schema_id: Uuid,
    pub issuer_did: Uuid,
    pub transport: String,
    #[convert(with_fn = convert_inner)]
    pub claim_values: Vec<CredentialRequestClaimRestDTO>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[convert(into = CredentialRequestClaimDTO)]
pub struct CredentialRequestClaimRestDTO {
    #[convert(rename = "claim_schema_id")]
    pub claim_id: Uuid,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CredentialRevocationCheckRequestRestDTO {
    pub credential_ids: Vec<Uuid>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[convert(from = "CredentialRevocationCheckResponseDTO")]
pub struct CredentialRevocationCheckResponseRestDTO {
    pub credential_id: Uuid,
    pub status: CredentialStateRestEnum,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}
