use one_dto_mapper::{From, Into, convert_inner, convert_inner_of_inner};
use serde::{Deserialize, Serialize};
use serde_with::{DurationSeconds, serde_as, skip_serializing_none};
use shared_types::i18n::I18nString;
use shared_types::{
    ClaimSchemaId, CredentialFormat, CredentialSchemaId, EcosystemId, OrganisationId,
    RevocationMethodId,
};
use standardized_types::etsi_119_472::disclosure_policy::DisclosurePolicy;
use standardized_types::openid4vp::dcql;
use strum::{Display, EnumString};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::model;
use crate::model::common::GetListResponse;
use crate::model::credential_schema::{
    CredentialSchemaExactColumn, KeyStorageSecurity, LayoutType, TransactionCode,
    TransactionCodeType,
};
use crate::model::list_filter::{ListFilterValue, StringMatch, ValueComparison};
pub use crate::proto::credential_schema::dto::CredentialClaimSchemaMappingDTO;
use crate::proto::credential_schema::transaction_code::TransactionCodeLength;
use crate::service::common_dto::{BoundedB64Image, KB, MB};

pub type CredentialSchemaLogo = BoundedB64Image<{ 500 * KB }>;
#[allow(clippy::identity_op)]
pub type CredentialBackgroundImage = BoundedB64Image<{ 1 * MB }>;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
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
    pub revocation_method: Option<RevocationMethodId>,
    pub key_storage_security: Option<KeyStorageSecurity>,
    pub schema_id: String,
    pub imported_source_url: String,
    pub layout_type: Option<LayoutType>,
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesResponseDTO>,
    pub allow_suspension: bool,
    pub requires_wallet_instance_attestation: bool,
    pub translations: Option<CredentialSchemaTranslationsDTO>,
    pub ecosystem: Option<EcosystemId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchemaFormatResponseDTO {
    pub format: CredentialFormat,
    pub schema_id: String,
    pub dcql: Option<CredentialSchemaDcqlResponseDTO>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialClaimSchemaV2DTO {
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
    pub claims: Vec<CredentialClaimSchemaV2DTO>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mappings: Option<Vec<CredentialClaimSchemaMappingDTO>>,
    pub translations: CredentialClaimSchemaTranslationsDTO,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchemaDetailV2ResponseDTO {
    pub id: CredentialSchemaId,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub formats: Vec<CredentialSchemaFormatResponseDTO>,
    pub organisation_id: OrganisationId,
    pub claims: Vec<CredentialClaimSchemaV2DTO>,
    pub key_storage_security: Option<KeyStorageSecurity>,
    pub imported_source_url: String,
    pub layout_type: Option<LayoutType>,
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesResponseDTO>,
    pub allow_suspension: bool,
    pub allow_revocation: Option<bool>,
    pub batch_size: Option<i32>,
    pub requires_wallet_instance_attestation: bool,
    pub transaction_code: Option<CredentialSchemaTransactionCodeDTO>,
    pub translations: CredentialSchemaTranslationsDTO,
    pub embedded_disclosure_policy: Option<DisclosurePolicy>,
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    pub expiration: Option<Duration>,
    pub ecosystem: Option<EcosystemId>,
}

#[serde_as]
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
    pub revocation_method: Option<RevocationMethodId>,
    pub organisation_id: OrganisationId,
    pub claims: Vec<CredentialClaimSchemaDTO>,
    pub key_storage_security: Option<KeyStorageSecurity>,
    pub schema_id: String,
    pub imported_source_url: String,
    pub layout_type: Option<LayoutType>,
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesResponseDTO>,
    pub allow_suspension: bool,
    pub requires_wallet_instance_attestation: bool,
    pub transaction_code: Option<CredentialSchemaTransactionCodeDTO>,
    pub dcql: Option<CredentialSchemaDcqlResponseDTO>,
    pub translations: CredentialSchemaTranslationsDTO,
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    pub expiration: Option<Duration>,
    pub ecosystem: Option<EcosystemId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct CredentialSchemaDcqlResponseDTO {
    #[serde(flatten)]
    pub format: dcql::CredentialFormat,
}

#[derive(Clone, Debug, Deserialize, Into, From)]
#[into(TransactionCode)]
#[from(TransactionCode)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchemaTransactionCodeDTO {
    pub r#type: TransactionCodeType,
    pub length: u32,
    pub description: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchemaTranslationsDTO {
    pub name: I18nString,
    pub description: Option<I18nString>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialClaimSchemaTranslationsDTO {
    pub name: I18nString,
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
    pub translations: CredentialClaimSchemaTranslationsDTO,
}

#[derive(Clone, Debug, Eq, PartialEq, EnumString, Display)]
#[strum(serialize_all = "camelCase")]
pub enum CredentialSchemaListIncludeEntityTypeEnum {
    LayoutProperties,
    Translations,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialSchemaFilterValue {
    Name(StringMatch),
    OrganisationId(OrganisationId),
    SchemaId(StringMatch),
    SchemaIds(Vec<String>),
    Formats(Vec<String>),
    Ecosystems(Vec<EcosystemId>),
    RequiresWalletInstanceAttestation(bool),
    KeyStorageSecurity(Vec<KeyStorageSecurity>),
    CredentialSchemaIds(Vec<CredentialSchemaId>),
    CreatedDate(ValueComparison<OffsetDateTime>),
    LastModified(ValueComparison<OffsetDateTime>),
    UsesBatchIssuance(bool),
    IsMultiformatSchema(bool),
    Expiration(ValueComparison<i64>),
}

impl ListFilterValue for CredentialSchemaFilterValue {}

#[derive(Clone, Debug)]
pub struct CredentialSchemaFilterParamsDTO {
    pub name: Option<String>,
    pub exact: Option<Vec<CredentialSchemaExactColumn>>,
    pub organisation_id: OrganisationId,
    pub schema_id: Option<String>,
    pub formats: Option<Vec<String>>,
    pub ecosystems: Option<Vec<EcosystemId>>,
    pub requires_wallet_instance_attestation: Option<bool>,
    pub key_storage_security: Option<Vec<KeyStorageSecurity>>,
    pub credential_schema_ids: Option<Vec<CredentialSchemaId>>,
    pub created_date_after: Option<OffsetDateTime>,
    pub created_date_before: Option<OffsetDateTime>,
    pub last_modified_after: Option<OffsetDateTime>,
    pub last_modified_before: Option<OffsetDateTime>,
    pub uses_batch_issuance: Option<bool>,
    pub is_multiformat_schema: Option<bool>,
    pub schema_ids: Option<Vec<String>>,
}

#[derive(Clone, Debug)]
pub struct CredentialSchemaV2FilterParamsDTO {
    pub name: Option<String>,
    pub exact: Option<Vec<CredentialSchemaExactColumn>>,
    pub organisation_id: OrganisationId,
    pub formats: Option<Vec<String>>,
    pub ecosystems: Option<Vec<EcosystemId>>,
    pub requires_wallet_instance_attestation: Option<bool>,
    pub key_storage_security: Option<Vec<KeyStorageSecurity>>,
    pub credential_schema_ids: Option<Vec<CredentialSchemaId>>,
    pub created_date_after: Option<OffsetDateTime>,
    pub created_date_before: Option<OffsetDateTime>,
    pub last_modified_after: Option<OffsetDateTime>,
    pub last_modified_before: Option<OffsetDateTime>,
    pub uses_batch_issuance: Option<bool>,
    pub is_multiformat_schema: Option<bool>,
    pub schema_ids: Option<Vec<String>>,
    pub expiration_greater_than: Option<Duration>,
    pub expiration_less_than: Option<Duration>,
}

pub type GetCredentialSchemaListResponseDTO = GetListResponse<CredentialSchemaListItemResponseDTO>;
pub type GetCredentialSchemaListV2ResponseDTO =
    GetListResponse<CredentialSchemaListItemV2ResponseDTO>;

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchemaListItemV2ResponseDTO {
    pub id: CredentialSchemaId,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub formats: Vec<CredentialSchemaFormatResponseDTO>,
    pub key_storage_security: Option<KeyStorageSecurity>,
    pub imported_source_url: String,
    pub layout_type: Option<LayoutType>,
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesResponseDTO>,
    pub allow_suspension: bool,
    pub allow_revocation: Option<bool>,
    pub batch_size: Option<i32>,
    pub requires_wallet_instance_attestation: bool,
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    pub expiration: Option<Duration>,
    pub ecosystem: Option<EcosystemId>,
}

#[derive(Clone, Debug)]
pub struct CreateCredentialSchemaV2RequestDTO {
    pub name: String,
    pub formats: Vec<CredentialSchemaFormatRequestDTO>,
    pub organisation_id: OrganisationId,
    pub claims: Vec<CredentialClaimSchemaRequestDTO>,
    pub key_storage_security: Option<KeyStorageSecurity>,
    pub layout_type: LayoutType,
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRequestDTO>,
    pub allow_suspension: Option<bool>,
    pub allow_revocation: Option<bool>,
    pub batch_size: Option<i32>,
    pub requires_wallet_instance_attestation: bool,
    pub transaction_code: Option<CredentialSchemaTransactionCodeRequestDTO>,
    pub translations: Option<CredentialSchemaTranslationsDTO>,
    pub embedded_disclosure_policy: Option<DisclosurePolicyCreateRequest>,
    pub expiration: Option<Duration>,
    pub ecosystem: Option<EcosystemId>,
}

#[derive(Clone, Debug)]
pub struct DisclosurePolicyCreateRequest {
    pub policy: standardized_types::etsi_119_472::disclosure_policy::PolicyType,
    pub description: Option<String>,
    pub url: Option<String>,
}

#[derive(Clone, Debug)]
pub struct CredentialSchemaFormatRequestDTO {
    pub format: CredentialFormat,
    pub schema_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Into)]
#[into(crate::proto::credential_schema::dto::ImportCredentialSchemaV2FormatDTO)]
#[serde(rename_all = "camelCase")]
pub struct ImportCredentialSchemaV2FormatDTO {
    pub format: CredentialFormat,
    pub schema_id: String,
}

#[derive(Clone, Debug)]
pub struct CreateCredentialSchemaRequestDTO {
    pub name: String,
    pub format: CredentialFormat,
    pub revocation_method: Option<RevocationMethodId>,
    pub organisation_id: OrganisationId,
    pub claims: Vec<CredentialClaimSchemaRequestDTO>,
    pub key_storage_security: Option<KeyStorageSecurity>,
    pub layout_type: LayoutType,
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRequestDTO>,
    pub schema_id: Option<String>,
    pub allow_suspension: Option<bool>,
    pub requires_wallet_instance_attestation: bool,
    pub transaction_code: Option<CredentialSchemaTransactionCodeRequestDTO>,
    pub ecosystem: Option<EcosystemId>,
}

#[derive(Clone, Debug, Into)]
#[into(TransactionCode)]
pub struct CredentialSchemaTransactionCodeRequestDTO {
    pub r#type: TransactionCodeType,
    pub length: TransactionCodeLength,
    pub description: Option<String>,
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
    #[from(with_fn = convert_inner_of_inner)]
    pub mappings: Option<Vec<CredentialClaimSchemaMappingDTO>>,
    #[from(replace = Option::<CredentialClaimSchemaTranslationsDTO>::None)]
    pub translations: Option<CredentialClaimSchemaTranslationsDTO>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Into, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[into(model::credential_schema::LayoutProperties)]
pub struct CredentialSchemaLayoutPropertiesRequestDTO {
    #[into(with_fn = convert_inner)]
    pub background: Option<CredentialSchemaBackgroundPropertiesRequestDTO>,
    #[into(with_fn = convert_inner)]
    pub logo: Option<CredentialSchemaLogoPropertiesRequestDTO>,
    pub primary_attribute: Option<String>,
    pub secondary_attribute: Option<String>,
    pub picture_attribute: Option<String>,
    #[into(with_fn = convert_inner)]
    pub code: Option<CredentialSchemaCodePropertiesDTO>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Into, From, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[into(model::credential_schema::LayoutProperties)]
#[from(model::credential_schema::LayoutProperties)]
pub struct CredentialSchemaLayoutPropertiesResponseDTO {
    #[from(with_fn = convert_inner)]
    #[into(with_fn = convert_inner)]
    pub background: Option<CredentialSchemaBackgroundPropertiesResponseDTO>,
    #[from(with_fn = convert_inner)]
    #[into(with_fn = convert_inner)]
    pub logo: Option<CredentialSchemaLogoPropertiesResponseDTO>,
    pub primary_attribute: Option<String>,
    pub secondary_attribute: Option<String>,
    pub picture_attribute: Option<String>,
    #[from(with_fn = convert_inner)]
    #[into(with_fn = convert_inner)]
    pub code: Option<CredentialSchemaCodePropertiesDTO>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Into, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[into(model::credential_schema::BackgroundProperties)]
pub struct CredentialSchemaBackgroundPropertiesRequestDTO {
    pub color: Option<String>,
    #[into(with_fn = convert_inner)]
    pub image: Option<CredentialBackgroundImage>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, From, Into, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[from(model::credential_schema::BackgroundProperties)]
#[into(model::credential_schema::BackgroundProperties)]
pub struct CredentialSchemaBackgroundPropertiesResponseDTO {
    pub color: Option<String>,
    pub image: Option<String>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Into, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[into(model::credential_schema::LogoProperties)]
pub struct CredentialSchemaLogoPropertiesRequestDTO {
    pub font_color: Option<String>,
    pub background_color: Option<String>,
    #[into(with_fn = convert_inner)]
    pub image: Option<CredentialSchemaLogo>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Into, From, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[from(model::credential_schema::LogoProperties)]
#[into(model::credential_schema::LogoProperties)]
pub struct CredentialSchemaLogoPropertiesResponseDTO {
    pub font_color: Option<String>,
    pub background_color: Option<String>,
    pub image: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Into, From, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[into(model::credential_schema::CodeProperties)]
#[from(model::credential_schema::CodeProperties)]
pub struct CredentialSchemaCodePropertiesDTO {
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

#[derive(Clone, Debug)]
pub struct CredentialSchemaShareResponseDTO {
    pub url: String,
}

#[derive(Clone, Debug)]
pub struct ImportCredentialSchemaRequestDTO {
    pub organisation_id: OrganisationId,
    pub schema: ImportCredentialSchemaRequestSchemaDTO,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Into)]
#[into(crate::proto::credential_schema::dto::ImportCredentialSchemaRequestSchemaDTO)]
#[serde(rename_all = "camelCase")]
pub struct ImportCredentialSchemaRequestSchemaDTO {
    pub id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: String,
    #[into(with_fn = convert_inner)]
    pub revocation_method: Option<String>,
    pub organisation_id: Uuid,
    #[into(with_fn = convert_inner)]
    pub claims: Vec<ImportCredentialSchemaClaimSchemaDTO>,
    pub key_storage_security: Option<KeyStorageSecurity>,
    pub schema_id: String,
    pub imported_source_url: String,
    #[into(with_fn = convert_inner)]
    pub layout_type: Option<LayoutType>,
    #[into(with_fn = convert_inner)]
    pub layout_properties: Option<ImportCredentialSchemaLayoutPropertiesDTO>,
    pub allow_suspension: Option<bool>,
    pub requires_wallet_instance_attestation: Option<bool>,
    #[into(with_fn = convert_inner)]
    pub transaction_code: Option<ImportCredentialSchemaTransactionCodeDTO>,
    #[serde(default)]
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    pub expiration: Option<Duration>,
}

#[derive(Clone, Debug, Deserialize, Into)]
#[into(crate::proto::credential_schema::dto::ImportCredentialSchemaTransactionCodeDTO)]
#[serde(rename_all = "camelCase")]
pub struct ImportCredentialSchemaTransactionCodeDTO {
    pub r#type: TransactionCodeType,
    pub length: TransactionCodeLength,
    pub description: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Into)]
#[into(crate::proto::credential_schema::dto::ImportCredentialSchemaClaimSchemaDTO)]
#[serde(rename_all = "camelCase")]
pub struct ImportCredentialSchemaClaimSchemaDTO {
    pub id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub key: String,
    pub datatype: String,
    pub required: bool,
    pub array: Option<bool>,
    #[serde(default)]
    #[into(with_fn = convert_inner)]
    pub claims: Vec<ImportCredentialSchemaClaimSchemaDTO>,
    #[into(with_fn = convert_inner_of_inner)]
    pub mappings: Option<Vec<CredentialClaimSchemaMappingDTO>>,
    #[serde(default)]
    pub translations: Option<CredentialClaimSchemaTranslationsDTO>,
}

#[derive(Clone, Debug, Into, Deserialize)]
#[into(crate::proto::credential_schema::dto::ImportCredentialSchemaLayoutPropertiesDTO)]
#[serde(rename_all = "camelCase")]
pub struct ImportCredentialSchemaLayoutPropertiesDTO {
    #[serde(default)]
    #[into(with_fn = convert_inner)]
    pub background: Option<CredentialSchemaBackgroundPropertiesRequestDTO>,
    #[serde(default)]
    #[into(with_fn = convert_inner)]
    pub logo: Option<CredentialSchemaLogoPropertiesRequestDTO>,
    #[serde(default)]
    pub primary_attribute: Option<String>,
    #[serde(default)]
    pub secondary_attribute: Option<String>,
    #[serde(default)]
    pub picture_attribute: Option<String>,
    #[serde(default)]
    #[into(with_fn = convert_inner)]
    pub code: Option<CredentialSchemaCodePropertiesDTO>,
}

#[derive(Clone, Debug)]
pub struct ImportCredentialSchemaV2RequestDTO {
    pub organisation_id: OrganisationId,
    pub schema: ImportCredentialSchemaV2RequestSchemaDTO,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Into)]
#[into(crate::proto::credential_schema::dto::ImportCredentialSchemaV2RequestSchemaDTO)]
#[serde(rename_all = "camelCase")]
pub struct ImportCredentialSchemaV2RequestSchemaDTO {
    pub id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    #[into(with_fn = convert_inner)]
    pub formats: Vec<ImportCredentialSchemaV2FormatDTO>,
    pub organisation_id: Uuid,
    #[into(with_fn = convert_inner)]
    pub claims: Vec<ImportCredentialSchemaClaimSchemaDTO>,
    #[serde(default)]
    pub key_storage_security: Option<KeyStorageSecurity>,
    pub imported_source_url: String,
    #[serde(default)]
    #[into(with_fn = convert_inner)]
    pub layout_type: Option<LayoutType>,
    #[serde(default)]
    #[into(with_fn = convert_inner)]
    pub layout_properties: Option<ImportCredentialSchemaLayoutPropertiesDTO>,
    #[serde(default)]
    pub allow_suspension: Option<bool>,
    #[serde(default)]
    pub requires_wallet_instance_attestation: Option<bool>,
    #[serde(default)]
    #[into(with_fn = convert_inner)]
    pub transaction_code: Option<ImportCredentialSchemaTransactionCodeDTO>,
    #[serde(default)]
    pub allow_revocation: Option<bool>,
    #[serde(default)]
    pub batch_size: Option<i32>,
    #[serde(default)]
    pub translations: Option<CredentialSchemaTranslationsDTO>,
    #[serde(default)]
    pub embedded_disclosure_policy: Option<DisclosurePolicy>,
    #[serde(default)]
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    pub expiration: Option<Duration>,
}
