use serde::{Deserialize, Serialize};
use shared_types::CredentialSchemaId;
use time::OffsetDateTime;

use crate::service::credential_schema::dto::CredentialSchemaFilterValue;

use super::claim_schema::{ClaimSchema, ClaimSchemaRelations};
use super::common::GetListResponse;
use super::list_query::ListQuery;
use super::organisation::{Organisation, OrganisationRelations};

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
    pub schema_type: CredentialSchemaType,

    // Relations
    pub claim_schemas: Option<Vec<CredentialSchemaClaim>>,
    pub organisation: Option<Organisation>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum CredentialSchemaType {
    ProcivisOneSchema2024,
    FallbackSchema2024,
    Mdoc,
    #[serde(untagged)]
    Other(String),
}

impl CredentialSchemaType {
    pub(crate) fn supports_custom_layout(&self) -> bool {
        match self {
            Self::ProcivisOneSchema2024 => true,
            Self::FallbackSchema2024 | Self::Mdoc => false,
            Self::Other(_) => false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialSchemaClaim {
    pub schema: ClaimSchema,
    pub required: bool,
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
#[serde(rename_all = "UPPERCASE")]
pub enum WalletStorageTypeEnum {
    Hardware,
    Software,
}

#[derive(Clone, Debug, Eq, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LayoutType {
    Card,
    Document,
    SingleAttribute,
}

#[derive(Clone, Debug, Eq, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LayoutProperties {
    pub background: Option<BackgroundProperties>,
    pub logo: Option<LogoProperties>,
    pub primary_attribute: Option<String>,
    pub secondary_attribute: Option<String>,
    pub picture_attribute: Option<String>,
    pub code: Option<CodeProperties>,
}

#[derive(Clone, Debug, Eq, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BackgroundProperties {
    pub color: Option<String>,
    pub image: Option<String>,
}

#[derive(Clone, Debug, Eq, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LogoProperties {
    pub font_color: Option<String>,
    pub background_color: Option<String>,
    pub image: Option<String>,
}

#[derive(Clone, Debug, Eq, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CodeProperties {
    pub attribute: String,
    pub r#type: CodeTypeEnum,
}

#[derive(Clone, Debug, Eq, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CodeTypeEnum {
    Barcode,
    Mrz,
    QrCode,
}

pub type GetCredentialSchemaList = GetListResponse<CredentialSchema>;
pub type GetCredentialSchemaQuery =
    ListQuery<SortableCredentialSchemaColumn, CredentialSchemaFilterValue>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateCredentialSchemaRequest {
    pub id: CredentialSchemaId,
    pub revocation_method: Option<RevocationMethod>,
}
