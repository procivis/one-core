use crate::dto::common::ExactColumn;
use crate::dto::common::ListQueryParamsRest;
use crate::endpoint::credential_schema::dto::{
    CredentialClaimSchemaResponseRestDTO, CredentialSchemaListItemResponseRestDTO,
};
use crate::endpoint::did::dto::DidListItemResponseRestDTO;
use crate::serialize::front_time;
use crate::serialize::front_time_option;
use dto_mapper::{convert_inner, From, Into};
use one_core::service::credential::dto::CreateCredentialRequestDTO;
use one_core::service::credential::dto::CredentialDetailResponseDTO;
use one_core::service::credential::dto::CredentialListItemResponseDTO;
use one_core::service::credential::dto::CredentialRequestClaimDTO;
use one_core::service::credential::dto::CredentialRevocationCheckResponseDTO;
use one_core::service::credential::dto::CredentialRole;
use one_core::service::credential::dto::CredentialStateEnum;
use one_core::service::credential::dto::DetailCredentialClaimResponseDTO;
use one_core::service::credential::dto::DetailCredentialSchemaResponseDTO;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::IntoParams;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(CredentialListItemResponseDTO)]
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
    #[from(with_fn = convert_inner)]
    pub issuer_did: Option<DidListItemResponseRestDTO>,
    pub role: CredentialRoleRestEnum,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[from(CredentialDetailResponseDTO)]
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
    #[from(with_fn = convert_inner)]
    pub issuer_did: Option<DidListItemResponseRestDTO>,
    #[from(with_fn = convert_inner)]
    pub claims: Vec<CredentialDetailClaimResponseRestDTO>,
    pub redirect_uri: Option<String>,
    pub role: CredentialRoleRestEnum,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, Into, From)]
#[from(CredentialRole)]
#[into(CredentialRole)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CredentialRoleRestEnum {
    Holder,
    Issuer,
    Verifier,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(DetailCredentialSchemaResponseDTO)]
pub struct CredentialDetailSchemaResponseRestDTO {
    pub id: Uuid,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    #[serde(
        serialize_with = "front_time_option",
        skip_serializing_if = "Option::is_none"
    )]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub deleted_at: Option<OffsetDateTime>,
    pub name: String,
    pub format: String,
    pub revocation_method: String,
    pub organisation_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(DetailCredentialClaimResponseDTO)]
pub struct CredentialDetailClaimResponseRestDTO {
    pub schema: CredentialClaimSchemaResponseRestDTO,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, From)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[from(CredentialStateEnum)]
pub enum CredentialStateRestEnum {
    Created,
    Pending,
    Offered,
    Accepted,
    Rejected,
    Revoked,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct CredentialsFilterQueryParamsRest {
    pub organisation_id: Uuid,
    pub name: Option<String>,
    pub role: Option<CredentialRoleRestEnum>,
    #[param(inline, rename = "exact[]")]
    pub exact: Option<Vec<ExactColumn>>,
    #[param(inline, rename = "ids[]")]
    pub ids: Option<Vec<Uuid>>,
}

pub type GetCredentialQuery =
    ListQueryParamsRest<CredentialsFilterQueryParamsRest, SortableCredentialColumnRestEnum>;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into("one_core::model::credential::SortableCredentialColumn")]
pub enum SortableCredentialColumnRestEnum {
    CreatedDate,
    #[serde(rename = "schema.name")]
    SchemaName,
    IssuerDid,
    State,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into)]
#[into(CreateCredentialRequestDTO)]
#[serde(rename_all = "camelCase")]
pub struct CreateCredentialRequestRestDTO {
    pub credential_schema_id: Uuid,
    pub issuer_did: Uuid,
    pub issuer_key: Option<Uuid>,
    pub transport: String,
    #[into(with_fn = convert_inner)]
    pub claim_values: Vec<CredentialRequestClaimRestDTO>,
    pub redirect_uri: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(CredentialRequestClaimDTO)]
pub struct CredentialRequestClaimRestDTO {
    #[into(rename = "claim_schema_id")]
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
#[from(CredentialRevocationCheckResponseDTO)]
pub struct CredentialRevocationCheckResponseRestDTO {
    pub credential_id: Uuid,
    pub status: CredentialStateRestEnum,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}
