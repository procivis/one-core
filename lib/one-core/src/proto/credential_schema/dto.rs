use one_dto_mapper::{From, Into, convert_inner};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use shared_types::{CredentialFormat, CredentialSchemaId, OrganisationId, RevocationMethodId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model;
use crate::model::credential_schema::{
    CodeTypeEnum, KeyStorageSecurity, LayoutType, TransactionCodeType,
};
use crate::model::organisation::Organisation;
use crate::service::common_dto::{BoundedB64Image, KB, MB};

pub type CredentialSchemaLogo = BoundedB64Image<{ 500 * KB }>;
#[allow(clippy::identity_op)]
pub type CredentialBackgroundImage = BoundedB64Image<{ 1 * MB }>;

#[derive(Clone, Debug)]
pub struct ImportCredentialSchemaRequestDTO {
    pub organisation: Organisation,
    pub schema: ImportCredentialSchemaRequestSchemaDTO,
}

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
    pub layout_type: Option<LayoutType>,
    pub layout_properties: Option<ImportCredentialSchemaLayoutPropertiesDTO>,
    pub allow_suspension: Option<bool>,
    pub requires_wallet_instance_attestation: Option<bool>,
    pub transaction_code: Option<ImportCredentialSchemaTransactionCodeDTO>,
}

#[derive(Clone, Debug, Deserialize)]
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
    pub claims: Vec<ImportCredentialSchemaClaimSchemaDTO>,
}

#[derive(Clone, Debug, Deserialize, From, Into)]
#[serde(rename_all = "camelCase")]
#[from(model::credential_schema::TransactionCode)]
#[into(model::credential_schema::TransactionCode)]
pub struct ImportCredentialSchemaTransactionCodeDTO {
    pub r#type: TransactionCodeType,
    pub length: u32,
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
