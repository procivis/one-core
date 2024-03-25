use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::claim_schema::{ClaimSchema, ClaimSchemaRelations};
use super::common::{GetListQueryParams, GetListResponse};
use super::organisation::{Organisation, OrganisationRelations};

pub type CredentialSchemaId = Uuid;
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
    pub schema_type: CredentialSchemaType,
    pub schema_id: String,

    // Relations
    pub claim_schemas: Option<Vec<CredentialSchemaClaim>>,
    pub organisation: Option<Organisation>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum CredentialSchemaType {
    ProcivisOneSchema2024,
    FallbackSchema2024,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayoutType {
    Card,
    Document,
    SingleAttribute,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayoutProperties {
    pub background_color: Option<String>,
    pub background_image: Option<String>,
    pub label_color: Option<String>,
    pub label_image: Option<String>,
    pub primary_attribute: Option<String>,
    pub secondary_attribute: Option<String>,
}

pub type GetCredentialSchemaList = GetListResponse<CredentialSchema>;
pub type GetCredentialSchemaQuery = GetListQueryParams<SortableCredentialSchemaColumn>;

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct UpdateCredentialSchemaRequest {
    pub id: CredentialSchemaId,

    pub revocation_method: Option<RevocationMethod>,
}
