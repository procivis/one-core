use one_dto_mapper::{From, Into, TryFrom, convert_inner};
use serde::{Deserialize, Serialize};
use serde_with::{DurationSeconds, serde_as, skip_serializing_none};
use shared_types::{
    CredentialFormat, CredentialSchemaId, EcosystemId, OrganisationId, RevocationMethodId,
};
use standardized_types::etsi_119_472::disclosure_policy::DisclosurePolicy;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::model;
use crate::model::credential_schema::{CodeTypeEnum, KeyStorageSecurity, TransactionCodeType};
use crate::model::organisation::Organisation;
use crate::proto::credential_schema::transaction_code::TransactionCodeLength;
use crate::service::common_dto::{BoundedB64Image, KB, MB};
use crate::service::error::ValidationError;

pub type CredentialSchemaLogo = BoundedB64Image<{ 500 * KB }>;
#[allow(clippy::identity_op)]
pub type CredentialBackgroundImage = BoundedB64Image<{ 1 * MB }>;

#[derive(Clone, Debug)]
pub struct ImportCredentialSchemaRequestDTO {
    pub organisation: Organisation,
    pub schema: ImportCredentialSchemaRequestSchemaDTO,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportCredentialSchemaRequestSchemaDTO {
    pub id: CredentialSchemaId,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: CredentialFormat,
    pub revocation_method: Option<RevocationMethodId>,
    pub organisation_id: OrganisationId,
    pub claims: Vec<ImportCredentialSchemaClaimSchemaDTO>,
    pub key_storage_security: Option<KeyStorageSecurity>,
    pub schema_id: String,
    pub imported_source_url: String,
    pub layout_properties: Option<ImportCredentialSchemaLayoutPropertiesDTO>,
    pub allow_suspension: Option<bool>,
    pub requires_wallet_instance_attestation: Option<bool>,
    pub transaction_code: Option<ImportCredentialSchemaTransactionCodeDTO>,
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    pub expiration: Option<Duration>,
    pub ecosystem: Option<EcosystemId>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportCredentialSchemaClaimSchemaDTO {
    #[expect(unused)]
    pub id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    #[expect(unused)]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    #[expect(unused)]
    pub last_modified: OffsetDateTime,
    pub key: String,
    pub datatype: String,
    pub required: bool,
    pub array: Option<bool>,
    #[serde(default)]
    pub claims: Vec<ImportCredentialSchemaClaimSchemaDTO>,
    pub mappings: Option<Vec<CredentialClaimSchemaMappingDTO>>,
    pub translations:
        Option<crate::service::credential_schema::dto::CredentialClaimSchemaTranslationsDTO>,
}

#[derive(Clone, Debug)]
pub struct ImportCredentialSchemaV2FormatDTO {
    pub format: CredentialFormat,
    pub ecosystem_schema_id: String,
}

#[derive(Clone, Debug)]
pub struct ImportCredentialSchemaV2RequestDTO {
    pub organisation: Organisation,
    pub schema: ImportCredentialSchemaV2RequestSchemaDTO,
}

#[derive(Clone, Debug)]
pub struct ImportCredentialSchemaV2RequestSchemaDTO {
    #[allow(unused)]
    pub id: CredentialSchemaId,
    #[allow(unused)]
    pub created_date: OffsetDateTime,
    #[allow(unused)]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub formats: Vec<ImportCredentialSchemaV2FormatDTO>,
    #[allow(unused)]
    pub organisation_id: OrganisationId,
    pub claims: Vec<ImportCredentialSchemaClaimSchemaDTO>,
    pub key_storage_security: Option<KeyStorageSecurity>,
    pub imported_source_url: String,
    pub layout_properties: Option<ImportCredentialSchemaLayoutPropertiesDTO>,
    pub allow_suspension: Option<bool>,
    pub requires_wallet_instance_attestation: Option<bool>,
    pub transaction_code: Option<ImportCredentialSchemaTransactionCodeDTO>,
    pub allow_revocation: Option<bool>,
    pub batch_size: Option<i32>,
    pub translations:
        Option<crate::service::credential_schema::dto::CredentialSchemaTranslationsDTO>,
    pub embedded_disclosure_policy: Option<DisclosurePolicy>,
    pub expiration: Option<Duration>,
    pub ecosystem: Option<EcosystemId>,
}

#[derive(Clone, Debug, Deserialize, TryFrom, Into)]
#[serde(rename_all = "camelCase")]
#[into(model::credential_schema::TransactionCode)]
#[try_from(T = model::credential_schema::TransactionCode, Error = ValidationError)]
pub struct ImportCredentialSchemaTransactionCodeDTO {
    #[try_from(infallible)]
    pub r#type: TransactionCodeType,
    pub length: TransactionCodeLength,
    #[try_from(infallible)]
    pub description: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportCredentialSchemaLayoutPropertiesDTO {
    #[serde(default)]
    pub background: Option<CredentialSchemaBackgroundPropertiesRequestDTO>,
    #[serde(default)]
    pub logo: Option<CredentialSchemaLogoPropertiesRequestDTO>,
    #[serde(default)]
    pub primary_attribute: Option<String>,
    #[serde(default)]
    pub secondary_attribute: Option<String>,
    #[serde(default)]
    pub picture_attribute: Option<String>,
    #[serde(default)]
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
#[derive(Debug, Clone, PartialEq, Eq, Into, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[into(model::credential_schema::LogoProperties)]
pub struct CredentialSchemaLogoPropertiesRequestDTO {
    pub font_color: Option<String>,
    pub background_color: Option<String>,
    #[into(with_fn = convert_inner)]
    pub image: Option<CredentialSchemaLogo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Into, From, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[into(model::credential_schema::CodeProperties)]
#[from(model::credential_schema::CodeProperties)]
pub struct CredentialSchemaCodePropertiesDTO {
    pub attribute: String,
    pub r#type: CodeTypeEnum,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialClaimSchemaMappingDTO {
    pub format: CredentialFormat,
    pub technical_key: String,
    pub namespace: Option<String>,
}
