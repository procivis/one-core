use serde::{Deserialize, Serialize};
use shared_types::{ClaimSchemaId, OrganisationId};
use time::OffsetDateTime;

use dto_mapper::From;

use crate::model::credential_schema::WalletStorageTypeEnum;
use crate::model::{
    common::{GetListQueryParams, GetListResponse},
    credential_schema::{
        CredentialFormat, CredentialSchema, CredentialSchemaId, RevocationMethod,
        SortableCredentialSchemaColumn,
    },
};

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
}

#[derive(Clone, Debug, PartialEq)]
pub struct CredentialClaimSchemaRequestDTO {
    pub key: String,
    pub datatype: String,
    pub required: bool,
    pub claims: Vec<CredentialClaimSchemaRequestDTO>,
}
