use dto_mapper::{convert_inner, From, Into};
use one_core::service::credential_schema::dto::{
    CreateCredentialSchemaRequestDTO, CredentialClaimSchemaDTO, CredentialClaimSchemaRequestDTO,
    CredentialSchemaDetailResponseDTO, CredentialSchemaListIncludeEntityTypeEnum,
    CredentialSchemaListItemResponseDTO,
};
use serde::{Deserialize, Serialize};
use shared_types::{CredentialSchemaId, OrganisationId};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;

use crate::dto::common::ListQueryParamsRest;
use crate::serialize::{front_time, front_time_option};

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_storage_type: Option<WalletStorageTypeRestEnum>,
    pub schema_id: String,
    pub schema_type: CredentialSchemaType,
    #[from(with_fn = convert_inner)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layout_type: Option<CredentialSchemaLayoutType>,
    #[from(with_fn = convert_inner)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRestDTO>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize, From, Into)]
#[from(one_core::service::credential::dto::CredentialSchemaType)]
#[into(one_core::service::credential::dto::CredentialSchemaType)]
pub enum CredentialSchemaType {
    ProcivisOneSchema2024,
    FallbackSchema2024,
    #[serde(rename = "mdoc")]
    Mdoc,
    #[serde(untagged)]
    Other(String),
}

impl From<String> for CredentialSchemaType {
    fn from(value: String) -> Self {
        match value.as_str() {
            "ProcivisOneSchema2024" => CredentialSchemaType::ProcivisOneSchema2024,
            "FallbackSchema2024" => CredentialSchemaType::FallbackSchema2024,
            "mdoc" => CredentialSchemaType::Mdoc,
            _ => Self::Other(value),
        }
    }
}

impl<'a> utoipa::ToSchema<'a> for CredentialSchemaType {
    fn schema() -> (
        &'a str,
        utoipa::openapi::RefOr<utoipa::openapi::schema::Schema>,
    ) {
        let known = utoipa::openapi::ObjectBuilder::new()
            .schema_type(utoipa::openapi::SchemaType::String)
            .enum_values(Some([
                "ProcivisOneSchema2024",
                "FallbackSchema2024",
                "mdoc",
            ]));

        let schema = utoipa::openapi::schema::OneOfBuilder::new()
            .item(known)
            .item(utoipa::schema!(String))
            .into();

        ("CredentialSchemaType", schema)
    }
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
    pub schema_id: String,
    pub schema_type: CredentialSchemaType,
    #[from(with_fn = convert_inner)]
    pub layout_type: Option<CredentialSchemaLayoutType>,
    #[from(with_fn = convert_inner)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRestDTO>,
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
    pub array: bool,
    #[from(with_fn = convert_inner)]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<CredentialClaimSchemaResponseRestDTO>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum CredentialSchemasExactColumn {
    Name,
    SchemaId,
    Format,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchemasFilterQueryParamsRest {
    pub organisation_id: OrganisationId,
    pub name: Option<String>,
    #[param(inline, rename = "exact[]")]
    pub exact: Option<Vec<CredentialSchemasExactColumn>>,
    #[param(inline, rename = "ids[]")]
    pub ids: Option<Vec<CredentialSchemaId>>,
    pub schema_id: Option<String>,
    pub format: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(CredentialSchemaListIncludeEntityTypeEnum)]
pub enum CredentialSchemaListIncludeEntityTypeRestEnum {
    LayoutProperties,
}

pub type GetCredentialSchemaQuery = ListQueryParamsRest<
    CredentialSchemasFilterQueryParamsRest,
    SortableCredentialSchemaColumnRestEnum,
    CredentialSchemaListIncludeEntityTypeRestEnum,
>;

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
    Software,
    Hardware,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Validate, Into)]
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
    #[serde(default)]
    #[schema(default = CredentialSchemaLayoutType::default)]
    pub layout_type: CredentialSchemaLayoutType,
    #[into(with_fn = convert_inner)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRestDTO>,
    pub schema_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into, From, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[into(one_core::model::credential_schema::LayoutType)]
#[from(one_core::model::credential_schema::LayoutType)]
pub enum CredentialSchemaLayoutType {
    #[default]
    Card,
    Document,
    SingleAttribute,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema, Into)]
#[into(CredentialClaimSchemaRequestDTO)]
pub struct CredentialClaimSchemaRequestRestDTO {
    pub key: String,
    pub datatype: String,
    pub required: bool,
    pub array: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[into(with_fn = convert_inner)]
    pub claims: Vec<CredentialClaimSchemaRequestRestDTO>,
}

#[derive(Debug, Clone, PartialEq, Eq, Into, From, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[into(one_core::service::credential_schema::dto::CredentialSchemaLayoutPropertiesRequestDTO)]
#[from(one_core::service::credential_schema::dto::CredentialSchemaLayoutPropertiesRequestDTO)]
pub struct CredentialSchemaLayoutPropertiesRestDTO {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[from(with_fn = convert_inner)]
    #[into(with_fn = convert_inner)]
    pub background: Option<CredentialSchemaBackgroundPropertiesRestDTO>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[from(with_fn = convert_inner)]
    #[into(with_fn = convert_inner)]
    pub logo: Option<CredentialSchemaLogoPropertiesRestDTO>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_attribute: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secondary_attribute: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture_attribute: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[from(with_fn = convert_inner)]
    #[into(with_fn = convert_inner)]
    pub code: Option<CredentialSchemaCodePropertiesRestDTO>,
}

#[derive(Debug, Clone, PartialEq, Eq, Into, From, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[into(one_core::service::credential_schema::dto::CredentialSchemaBackgroundPropertiesRequestDTO)]
#[from(one_core::service::credential_schema::dto::CredentialSchemaBackgroundPropertiesRequestDTO)]
pub struct CredentialSchemaBackgroundPropertiesRestDTO {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Into, From, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[into(one_core::service::credential_schema::dto::CredentialSchemaLogoPropertiesRequestDTO)]
#[from(one_core::service::credential_schema::dto::CredentialSchemaLogoPropertiesRequestDTO)]
pub struct CredentialSchemaLogoPropertiesRestDTO {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub font_color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background_color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Into, From, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[into(one_core::service::credential_schema::dto::CredentialSchemaCodePropertiesRequestDTO)]
#[from(one_core::service::credential_schema::dto::CredentialSchemaCodePropertiesRequestDTO)]
pub struct CredentialSchemaCodePropertiesRestDTO {
    pub attribute: String,
    pub r#type: CredentialSchemaCodeTypeRestEnum,
}

#[derive(Debug, Clone, PartialEq, Eq, Into, From, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[into(one_core::service::credential_schema::dto::CredentialSchemaCodeTypeEnum)]
#[from(one_core::service::credential_schema::dto::CredentialSchemaCodeTypeEnum)]
pub enum CredentialSchemaCodeTypeRestEnum {
    Barcode,
    Mrz,
    QrCode,
}

#[derive(Debug, Clone, From, Serialize, ToSchema)]
#[from(one_core::service::credential_schema::dto::CredentialSchemaShareResponseDTO)]
pub struct CredentialSchemaShareResponseRestDTO {
    pub url: String,
}

#[derive(Clone, Debug, Deserialize, Into, ToSchema)]
#[into(one_core::service::credential_schema::dto::ImportCredentialSchemaRequestDTO)]
#[serde(rename_all = "camelCase")]
pub struct ImportCredentialSchemaRequestRestDTO {
    pub organisation_id: OrganisationId,
    pub schema: ImportCredentialSchemaRequestSchemaRestDTO,
}

#[derive(Clone, Debug, Deserialize, Into, ToSchema)]
#[into(one_core::service::credential_schema::dto::ImportCredentialSchemaRequestSchemaDTO)]
#[serde(rename_all = "camelCase")]
pub struct ImportCredentialSchemaRequestSchemaRestDTO {
    pub id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: String,
    pub revocation_method: String,
    pub organisation_id: Uuid,
    #[into(with_fn = convert_inner)]
    pub claims: Vec<ImportCredentialSchemaClaimSchemaRestDTO>,
    #[into(with_fn = convert_inner)]
    pub wallet_storage_type: Option<WalletStorageTypeRestEnum>,
    pub schema_id: String,
    pub imported_source_url: String,
    pub schema_type: CredentialSchemaType,
    #[into(with_fn = convert_inner)]
    pub layout_type: Option<CredentialSchemaLayoutType>,
    #[into(with_fn = convert_inner)]
    pub layout_properties: Option<ImportCredentialSchemaLayoutPropertiesRestDTO>,
}

#[derive(Clone, Debug, Deserialize, Into, ToSchema)]
#[into(one_core::service::credential_schema::dto::ImportCredentialSchemaClaimSchemaDTO)]
#[serde(rename_all = "camelCase")]
pub struct ImportCredentialSchemaClaimSchemaRestDTO {
    pub id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub key: String,
    pub datatype: String,
    pub required: bool,
    pub array: Option<bool>,
    #[into(with_fn = convert_inner)]
    #[serde(default)]
    pub claims: Vec<ImportCredentialSchemaClaimSchemaRestDTO>,
}

#[derive(Clone, Debug, Deserialize, Into, ToSchema)]
#[serde(rename_all = "camelCase")]
#[into(one_core::service::credential_schema::dto::ImportCredentialSchemaLayoutPropertiesDTO)]
pub struct ImportCredentialSchemaLayoutPropertiesRestDTO {
    #[serde(default)]
    #[into(with_fn = convert_inner)]
    pub background: Option<CredentialSchemaBackgroundPropertiesRestDTO>,
    #[serde(default)]
    #[into(with_fn = convert_inner)]
    pub logo: Option<CredentialSchemaLogoPropertiesRestDTO>,
    #[serde(default)]
    pub primary_attribute: Option<String>,
    #[serde(default)]
    pub secondary_attribute: Option<String>,
    #[serde(default)]
    pub picture_attribute: Option<String>,
    #[serde(default)]
    #[into(with_fn = convert_inner)]
    pub code: Option<CredentialSchemaCodePropertiesRestDTO>,
}
