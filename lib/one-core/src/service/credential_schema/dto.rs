use serde::{Deserialize, Serialize};
use shared_types::{ClaimSchemaId, OrganisationId};
use time::OffsetDateTime;

use dto_mapper::{From, Into};

use crate::model;
use crate::model::credential_schema::{LayoutType, WalletStorageTypeEnum};
use crate::model::{
    common::{GetListQueryParams, GetListResponse},
    credential_schema::{
        CredentialFormat, CredentialSchema, CredentialSchemaId, RevocationMethod,
        SortableCredentialSchemaColumn,
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
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialSchemaDetailResponseDTO {
    pub id: CredentialSchemaId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: CredentialFormat,
    pub revocation_method: RevocationMethod,
    pub organisation_id: OrganisationId,
    pub claims: Vec<CredentialClaimSchemaDTO>,
    pub wallet_storage_type: Option<WalletStorageTypeEnum>,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<CredentialClaimSchemaDTO>,
}

pub type GetCredentialSchemaListResponseDTO = GetListResponse<CredentialSchemaListItemResponseDTO>;
pub type GetCredentialSchemaQueryDTO = GetListQueryParams<SortableCredentialSchemaColumn>;

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
}

#[derive(Debug, Clone, Into)]
#[into(model::credential_schema::LayoutProperties)]
pub struct CredentialSchemaLayoutPropertiesRequestDTO {
    pub background_color: Option<String>,
    pub background_image: Option<String>,
    pub label_color: Option<String>,
    pub label_image: Option<String>,
    pub primary_attribute: Option<String>,
    pub secondary_attribute: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CredentialClaimSchemaRequestDTO {
    pub key: String,
    pub datatype: String,
    pub required: bool,
    pub claims: Vec<CredentialClaimSchemaRequestDTO>,
}
