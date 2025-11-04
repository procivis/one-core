use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use shared_types::CredentialSchemaId;
use strum::{Display, EnumString};
use time::OffsetDateTime;

use super::claim_schema::{ClaimSchema, ClaimSchemaRelations};
use super::common::GetListResponse;
use super::list_query::ListQuery;
use super::organisation::{Organisation, OrganisationRelations};
use crate::service::credential_schema::dto::{
    CredentialSchemaFilterValue, CredentialSchemaListIncludeEntityTypeEnum,
};

pub type CredentialSchemaName = String;
pub type CredentialFormat = String;
pub type RevocationMethod = String;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialSchema {
    pub id: CredentialSchemaId,
    pub deleted_at: Option<OffsetDateTime>,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: CredentialSchemaName,
    pub format: CredentialFormat,
    pub revocation_method: RevocationMethod,
    pub wallet_storage_type: Option<WalletStorageTypeEnum>,
    pub layout_type: LayoutType,
    pub layout_properties: Option<LayoutProperties>,
    pub schema_id: String,
    pub imported_source_url: String,
    pub allow_suspension: bool,
    pub requires_app_attestation: bool,

    // Relations
    pub claim_schemas: Option<Vec<CredentialSchemaClaim>>,
    pub organisation: Option<Organisation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialSchemaClaim {
    pub schema: ClaimSchema,
    pub required: bool,
}

#[derive(Debug)]
pub(crate) struct CredentialSchemaClaimsNestedView {
    pub fields: HashMap<String, Arrayed<CredentialSchemaClaimsNestedTypeView>>,
}

#[derive(Debug)]
pub enum Arrayed<T> {
    InArray(T),
    Single(T),
}

#[derive(Debug)]
pub(crate) enum CredentialSchemaClaimsNestedTypeView {
    Field(CredentialSchemaClaim),
    Object(CredentialSchemaClaimsNestedObjectView),
}

#[derive(Debug)]
pub(crate) struct CredentialSchemaClaimsNestedObjectView {
    pub claim: CredentialSchemaClaim,
    pub fields: HashMap<String, Arrayed<CredentialSchemaClaimsNestedTypeView>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct CredentialSchemaRelations {
    pub claim_schemas: Option<ClaimSchemaRelations>,
    pub organisation: Option<OrganisationRelations>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableCredentialSchemaColumn {
    Name,
    Format,
    CreatedDate,
}

#[derive(Clone, Debug, Eq, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LayoutType {
    Card,
    Document,
    SingleAttribute,
}

#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    Serialize,
    Deserialize,
    PartialEq,
    Display,
    EnumString,
    Hash,
    PartialOrd,
    Ord,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WalletStorageTypeEnum {
    Hardware,
    Software,
    RemoteSecureElement,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Eq, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct LayoutProperties {
    pub background: Option<BackgroundProperties>,
    pub logo: Option<LogoProperties>,
    pub primary_attribute: Option<String>,
    pub secondary_attribute: Option<String>,
    pub picture_attribute: Option<String>,
    pub code: Option<CodeProperties>,
}

#[derive(Clone, Debug, Eq, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct BackgroundProperties {
    pub color: Option<String>,
    pub image: Option<String>,
}

#[derive(Clone, Debug, Eq, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct LogoProperties {
    pub font_color: Option<String>,
    pub background_color: Option<String>,
    pub image: Option<String>,
}

#[derive(Clone, Debug, Eq, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CodeProperties {
    pub attribute: String,
    pub r#type: CodeTypeEnum,
}

#[derive(Clone, Debug, Eq, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CodeTypeEnum {
    Barcode,
    Mrz,
    QrCode,
}

pub type GetCredentialSchemaList = GetListResponse<CredentialSchema>;
pub type GetCredentialSchemaQuery = ListQuery<
    SortableCredentialSchemaColumn,
    CredentialSchemaFilterValue,
    CredentialSchemaListIncludeEntityTypeEnum,
>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateCredentialSchemaRequest {
    pub id: CredentialSchemaId,
    pub revocation_method: Option<RevocationMethod>,
    pub format: Option<String>,
    pub claim_schemas: Option<Vec<CredentialSchemaClaim>>,
    pub layout_type: Option<LayoutType>,
    pub layout_properties: Option<LayoutProperties>,
}
