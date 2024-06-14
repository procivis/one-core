use serde::{Deserialize, Serialize};
use shared_types::{ClaimSchemaId, CredentialSchemaId, OrganisationId};
use strum_macros::{Display, EnumString};
use time::OffsetDateTime;

use dto_mapper::{convert_inner, From, Into};
use uuid::Uuid;

use crate::model;
use crate::model::credential_schema::{LayoutType, WalletStorageTypeEnum};
use crate::model::list_filter::{ListFilterValue, StringMatch};
use crate::model::list_query::ListQuery;
use crate::model::{
    common::GetListResponse,
    credential_schema::{
        CredentialFormat, CredentialSchema, RevocationMethod, SortableCredentialSchemaColumn,
    },
};
use crate::service::credential::dto::CredentialSchemaType;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, From)]
#[from(CredentialSchema)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchemaListItemResponseDTO {
    pub id: CredentialSchemaId,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    #[serde(skip)]
    pub deleted_at: Option<OffsetDateTime>,
    pub name: String,
    pub format: CredentialFormat,
    pub revocation_method: RevocationMethod,
    pub wallet_storage_type: Option<WalletStorageTypeEnum>,
    pub schema_id: String,
    pub schema_type: CredentialSchemaType,
    pub layout_type: Option<LayoutType>,
    #[from(with_fn = convert_inner)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRequestDTO>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchemaDetailResponseDTO {
    pub id: CredentialSchemaId,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: CredentialFormat,
    pub revocation_method: RevocationMethod,
    pub organisation_id: OrganisationId,
    pub claims: Vec<CredentialClaimSchemaDTO>,
    pub wallet_storage_type: Option<WalletStorageTypeEnum>,
    pub schema_id: String,
    pub schema_type: CredentialSchemaType,
    pub layout_type: Option<LayoutType>,
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRequestDTO>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialClaimSchemaDTO {
    pub id: ClaimSchemaId,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub key: String,
    pub datatype: String,
    pub required: bool,
    pub array: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<CredentialClaimSchemaDTO>,
}

#[derive(Clone, Debug, Eq, PartialEq, EnumString, Display)]
#[strum(serialize_all = "camelCase")]
pub enum CredentialSchemaListIncludeEntityTypeEnum {
    LayoutProperties,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialSchemaFilterValue {
    Name(StringMatch),
    OrganisationId(OrganisationId),
    SchemaId(StringMatch),
    Format(StringMatch),
    CredentialSchemaIds(Vec<CredentialSchemaId>),
}

impl ListFilterValue for CredentialSchemaFilterValue {}

pub type GetCredentialSchemaListResponseDTO = GetListResponse<CredentialSchemaListItemResponseDTO>;
pub type GetCredentialSchemaQueryDTO = ListQuery<
    SortableCredentialSchemaColumn,
    CredentialSchemaFilterValue,
    CredentialSchemaListIncludeEntityTypeEnum,
>;

#[derive(Clone, Debug)]
pub struct CreateCredentialSchemaRequestDTO {
    pub name: String,
    pub format: String,
    pub revocation_method: String,
    pub organisation_id: OrganisationId,
    pub claims: Vec<CredentialClaimSchemaRequestDTO>,
    pub wallet_storage_type: Option<WalletStorageTypeEnum>,
    pub layout_type: LayoutType,
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRequestDTO>,
    pub schema_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, From)]
#[from(ImportCredentialSchemaClaimSchemaDTO)]
pub struct CredentialClaimSchemaRequestDTO {
    pub key: String,
    pub datatype: String,
    pub required: bool,
    pub array: Option<bool>,
    #[from(with_fn = convert_inner)]
    pub claims: Vec<CredentialClaimSchemaRequestDTO>,
}

#[derive(Debug, Clone, PartialEq, Eq, Into, From, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[into(model::credential_schema::LayoutProperties)]
#[from(model::credential_schema::LayoutProperties)]
pub struct CredentialSchemaLayoutPropertiesRequestDTO {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[from(with_fn = convert_inner)]
    #[into(with_fn = convert_inner)]
    pub background: Option<CredentialSchemaBackgroundPropertiesRequestDTO>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[from(with_fn = convert_inner)]
    #[into(with_fn = convert_inner)]
    pub logo: Option<CredentialSchemaLogoPropertiesRequestDTO>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_attribute: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secondary_attribute: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture_attribute: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[from(with_fn = convert_inner)]
    #[into(with_fn = convert_inner)]
    pub code: Option<CredentialSchemaCodePropertiesRequestDTO>,
}

#[derive(Debug, Clone, PartialEq, Eq, Into, From, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[into(model::credential_schema::BackgroundProperties)]
#[from(model::credential_schema::BackgroundProperties)]
pub struct CredentialSchemaBackgroundPropertiesRequestDTO {
    pub color: Option<String>,
    pub image: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Into, From, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[into(model::credential_schema::LogoProperties)]
#[from(model::credential_schema::LogoProperties)]
pub struct CredentialSchemaLogoPropertiesRequestDTO {
    pub font_color: Option<String>,
    pub background_color: Option<String>,
    pub image: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Into, From, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[into(model::credential_schema::CodeProperties)]
#[from(model::credential_schema::CodeProperties)]
pub struct CredentialSchemaCodePropertiesRequestDTO {
    pub attribute: String,
    pub r#type: CredentialSchemaCodeTypeEnum,
}

#[derive(Debug, Clone, PartialEq, Eq, Into, From, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[into(model::credential_schema::CodeTypeEnum)]
#[from(model::credential_schema::CodeTypeEnum)]
pub enum CredentialSchemaCodeTypeEnum {
    Barcode,
    Mrz,
    QrCode,
}

pub struct CredentialSchemaShareResponseDTO {
    pub url: String,
}

#[derive(Clone, Debug)]
pub struct ImportCredentialSchemaRequestDTO {
    pub organisation_id: OrganisationId,
    pub schema: ImportCredentialSchemaRequestSchemaDTO,
}

#[derive(Clone, Debug)]
pub struct ImportCredentialSchemaRequestSchemaDTO {
    pub id: Uuid,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: String,
    pub revocation_method: String,
    pub organisation_id: Uuid,
    pub claims: Vec<ImportCredentialSchemaClaimSchemaDTO>,
    pub wallet_storage_type: Option<WalletStorageTypeEnum>,
    pub schema_id: String,
    pub schema_type: CredentialSchemaType,
    pub layout_type: Option<LayoutType>,
    pub layout_properties: Option<ImportCredentialSchemaLayoutPropertiesDTO>,
}

#[derive(Clone, Debug)]
pub struct ImportCredentialSchemaClaimSchemaDTO {
    pub id: Uuid,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub key: String,
    pub datatype: String,
    pub required: bool,
    pub array: Option<bool>,
    pub claims: Vec<ImportCredentialSchemaClaimSchemaDTO>,
}

#[derive(Clone, Debug, Into)]
#[into(CredentialSchemaLayoutPropertiesRequestDTO)]
pub struct ImportCredentialSchemaLayoutPropertiesDTO {
    #[into(with_fn = convert_inner)]
    pub background: Option<CredentialSchemaBackgroundPropertiesRequestDTO>,
    #[into(with_fn = convert_inner)]
    pub logo: Option<CredentialSchemaLogoPropertiesRequestDTO>,
    pub primary_attribute: Option<String>,
    pub secondary_attribute: Option<String>,
    pub picture_attribute: Option<String>,
    #[into(with_fn = convert_inner)]
    pub code: Option<CredentialSchemaCodePropertiesRequestDTO>,
}
