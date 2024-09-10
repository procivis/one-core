use dto_mapper::{convert_inner, convert_inner_of_inner, From, Into};
use one_providers::common_models::credential_schema::OpenWalletStorageTypeEnum;
use serde::{Deserialize, Serialize};
use shared_types::CredentialSchemaId;
use strum::Display;
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

#[derive(Clone, Debug, Eq, PartialEq, Into, From)]
#[into(one_providers::common_models::credential_schema::OpenCredentialSchema)]
#[from(one_providers::common_models::credential_schema::OpenCredentialSchema)]
pub struct CredentialSchema {
    pub id: CredentialSchemaId,
    pub deleted_at: Option<OffsetDateTime>,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: CredentialSchemaName,
    pub format: CredentialFormat,
    pub revocation_method: RevocationMethod,
    #[into(with_fn = "convert_inner")]
    #[from(with_fn = "convert_inner")]
    pub wallet_storage_type: Option<OpenWalletStorageTypeEnum>,
    pub layout_type: LayoutType,
    #[into(with_fn = "convert_inner")]
    #[from(with_fn = "convert_inner")]
    pub layout_properties: Option<LayoutProperties>,
    pub schema_id: String,
    #[into(with_fn_ref = "ToString::to_string")]
    pub schema_type: CredentialSchemaType,

    // Relations
    #[into(with_fn = "convert_inner_of_inner")]
    #[from(with_fn = "convert_inner_of_inner")]
    pub claim_schemas: Option<Vec<CredentialSchemaClaim>>,
    #[into(with_fn = "convert_inner")]
    #[from(with_fn = "convert_inner")]
    pub organisation: Option<Organisation>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Display)]
pub enum CredentialSchemaType {
    #[strum(serialize = "ProcivisOneSchema2024")]
    ProcivisOneSchema2024,
    #[strum(serialize = "FallbackSchema2024")]
    FallbackSchema2024,
    #[strum(serialize = "mdoc")]
    Mdoc,
    #[strum(serialize = "{0}")]
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

#[derive(Clone, Debug, Eq, PartialEq, From, Into)]
#[from(one_providers::common_models::credential_schema::OpenCredentialSchemaClaim)]
#[into(one_providers::common_models::credential_schema::OpenCredentialSchemaClaim)]
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

#[derive(Clone, Debug, Eq, Serialize, Deserialize, PartialEq, From, Into)]
#[from(one_providers::common_models::credential_schema::OpenLayoutType)]
#[into(one_providers::common_models::credential_schema::OpenLayoutType)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LayoutType {
    Card,
    Document,
    SingleAttribute,
}

#[derive(Clone, Debug, Eq, Deserialize, PartialEq, From, Into, Default)]
#[from(one_providers::common_models::credential_schema::OpenLayoutProperties)]
#[into(one_providers::common_models::credential_schema::OpenLayoutProperties)]
#[serde(rename_all = "camelCase")]
pub struct LayoutProperties {
    #[from(with_fn = "convert_inner")]
    #[into(with_fn = "convert_inner")]
    pub background: Option<BackgroundProperties>,
    #[from(with_fn = "convert_inner")]
    #[into(with_fn = "convert_inner")]
    pub logo: Option<LogoProperties>,
    pub primary_attribute: Option<String>,
    pub secondary_attribute: Option<String>,
    pub picture_attribute: Option<String>,
    #[from(with_fn = "convert_inner")]
    #[into(with_fn = "convert_inner")]
    pub code: Option<CodeProperties>,
}

#[derive(Clone, Debug, Eq, Deserialize, PartialEq, From, Into)]
#[from(one_providers::common_models::credential_schema::OpenBackgroundProperties)]
#[into(one_providers::common_models::credential_schema::OpenBackgroundProperties)]
#[serde(rename_all = "camelCase")]
pub struct BackgroundProperties {
    pub color: Option<String>,
    pub image: Option<String>,
}

#[derive(Clone, Debug, Eq, Deserialize, PartialEq, From, Into)]
#[from(one_providers::common_models::credential_schema::OpenLogoProperties)]
#[into(one_providers::common_models::credential_schema::OpenLogoProperties)]
#[serde(rename_all = "camelCase")]
pub struct LogoProperties {
    pub font_color: Option<String>,
    pub background_color: Option<String>,
    pub image: Option<String>,
}

#[derive(Clone, Debug, Eq, Deserialize, PartialEq, From, Into)]
#[from(one_providers::common_models::credential_schema::OpenCodeProperties)]
#[into(one_providers::common_models::credential_schema::OpenCodeProperties)]
#[serde(rename_all = "camelCase")]
pub struct CodeProperties {
    pub attribute: String,
    pub r#type: CodeTypeEnum,
}

#[derive(Clone, Debug, Eq, Deserialize, PartialEq, From, Into)]
#[from(one_providers::common_models::credential_schema::OpenCodeTypeEnum)]
#[into(one_providers::common_models::credential_schema::OpenCodeTypeEnum)]
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

#[derive(Clone, Debug, Eq, PartialEq, From)]
#[from(one_providers::common_models::credential_schema::OpenUpdateCredentialSchemaRequest)]
pub struct UpdateCredentialSchemaRequest {
    pub id: CredentialSchemaId,
    pub revocation_method: Option<RevocationMethod>,
    pub format: Option<String>,
    #[from(with_fn = convert_inner_of_inner)]
    pub claim_schemas: Option<Vec<CredentialSchemaClaim>>,
    #[from(with_fn = convert_inner)]
    pub layout_type: Option<LayoutType>,
    #[from(with_fn = convert_inner)]
    pub layout_properties: Option<LayoutProperties>,
}
