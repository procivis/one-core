use dto_mapper::convert_inner;
use dto_mapper::{From, Into};
use one_core::service::credential_schema::dto::{
    CreateCredentialSchemaRequestDTO, CredentialClaimSchemaDTO, CredentialClaimSchemaRequestDTO,
    CredentialSchemaDetailResponseDTO, CredentialSchemaListItemResponseDTO,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

use crate::serialize::{front_time, front_time_option};

use crate::dto::common::GetListQueryParams;

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(CredentialSchemaListItemResponseDTO)]
pub struct CredentialSchemaListItemResponseRestDTO {
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
    pub format: String,
    pub revocation_method: String,
    #[from(with_fn = convert_inner)]
    pub wallet_storage_type: Option<WalletStorageTypeRestEnum>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[from(CredentialSchemaDetailResponseDTO)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchemaResponseRestDTO {
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
    #[from(with_fn = convert_inner)]
    pub claims: Vec<CredentialClaimSchemaResponseRestDTO>,
    #[from(with_fn = convert_inner)]
    pub wallet_storage_type: Option<WalletStorageTypeRestEnum>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(CredentialClaimSchemaDTO)]
pub struct CredentialClaimSchemaResponseRestDTO {
    pub id: Uuid,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub key: String,
    pub datatype: String,
    pub required: bool,
    #[from(with_fn = convert_inner)]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<CredentialClaimSchemaResponseRestDTO>,
}

pub type GetCredentialSchemaQuery = GetListQueryParams<SortableCredentialSchemaColumnRestEnum>;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into("one_core::model::credential_schema::SortableCredentialSchemaColumn")]
pub enum SortableCredentialSchemaColumnRestEnum {
    Name,
    Format,
    CreatedDate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, Into, From)]
#[serde(rename_all = "UPPERCASE")]
#[into("one_core::model::credential_schema::WalletStorageTypeEnum")]
#[from("one_core::model::credential_schema::WalletStorageTypeEnum")]
pub enum WalletStorageTypeRestEnum {
    Hardware,
    Software,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema, Validate, Into)]
#[into(CreateCredentialSchemaRequestDTO)]
#[serde(rename_all = "camelCase")]
pub struct CreateCredentialSchemaRequestRestDTO {
    #[validate(length(min = 1))]
    pub name: String,
    pub format: String,
    pub revocation_method: String,
    pub organisation_id: Uuid,
    #[into(with_fn = convert_inner)]
    #[validate(length(min = 1))]
    pub claims: Vec<CredentialClaimSchemaRequestRestDTO>,
    #[into(with_fn = convert_inner)]
    pub wallet_storage_type: Option<WalletStorageTypeRestEnum>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema, Into)]
#[into(CredentialClaimSchemaRequestDTO)]
pub struct CredentialClaimSchemaRequestRestDTO {
    pub key: String,
    pub datatype: String,
    pub required: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[into(with_fn = convert_inner)]
    pub claims: Vec<CredentialClaimSchemaRequestRestDTO>,
}
