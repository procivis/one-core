use serde::{Deserialize, Serialize};
use shared_types::{ClaimSchemaId, CredentialId, DidId, KeyId, OrganisationId};
use strum_macros::AsRefStr;
use time::OffsetDateTime;
use uuid::Uuid;

use dto_mapper::From;

use crate::model::credential_schema::WalletStorageTypeEnum;
use crate::model::list_filter::ValueComparison;
use crate::{
    model::{
        common::GetListResponse,
        credential::SortableCredentialColumn,
        credential_schema::{CredentialFormat, CredentialSchemaId, RevocationMethod},
        list_filter::{ListFilterValue, StringMatch},
        list_query::ListQuery,
    },
    service::{
        credential_schema::dto::{CredentialClaimSchemaDTO, CredentialSchemaListItemResponseDTO},
        did::dto::DidListItemResponseDTO,
    },
};

#[derive(Clone, Debug)]
pub struct CredentialListItemResponseDTO {
    pub id: CredentialId,
    pub created_date: OffsetDateTime,
    pub issuance_date: OffsetDateTime,
    pub revocation_date: Option<OffsetDateTime>,
    pub state: CredentialStateEnum,
    pub last_modified: OffsetDateTime,
    pub schema: CredentialSchemaListItemResponseDTO,
    pub issuer_did: Option<DidListItemResponseDTO>,
    pub credential: Vec<u8>,
    pub role: CredentialRole,
    pub suspend_end_date: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialDetailResponseDTO {
    pub id: CredentialId,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub issuance_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub revocation_date: Option<OffsetDateTime>,
    pub state: CredentialStateEnum,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub schema: DetailCredentialSchemaResponseDTO,
    pub issuer_did: Option<DidListItemResponseDTO>,
    pub claims: Vec<DetailCredentialClaimResponseDTO>,
    pub redirect_uri: Option<String>,
    pub role: CredentialRole,
    #[serde(with = "time::serde::rfc3339::option")]
    pub lvvc_issuance_date: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub suspend_end_date: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetailCredentialSchemaResponseDTO {
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
    pub organisation_id: OrganisationId,
    pub wallet_storage_type: Option<WalletStorageTypeEnum>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetailCredentialClaimResponseDTO {
    pub schema: CredentialClaimSchemaDTO,
    pub value: String,
}

#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize, From, AsRefStr)]
#[from("crate::model::credential::CredentialRole")]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum CredentialRole {
    Holder,
    Issuer,
    Verifier,
}

#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize, From)]
#[from("crate::model::credential::CredentialStateEnum")]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CredentialStateEnum {
    Created,
    Pending,
    Offered,
    Accepted,
    Rejected,
    Revoked,
    Suspended,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialFilterValue {
    Name(StringMatch),
    OrganisationId(OrganisationId),
    Role(CredentialRole),
    CredentialIds(Vec<CredentialId>),
    State(crate::model::credential::CredentialStateEnum),
    SuspendEndDate(ValueComparison<OffsetDateTime>),
}

impl ListFilterValue for CredentialFilterValue {}

pub type GetCredentialListResponseDTO = GetListResponse<CredentialListItemResponseDTO>;
pub type GetCredentialQueryDTO = ListQuery<SortableCredentialColumn, CredentialFilterValue>;

#[derive(Clone, Debug)]
pub struct CreateCredentialRequestDTO {
    pub credential_schema_id: Uuid,
    pub issuer_did: DidId,
    pub issuer_key: Option<KeyId>,
    pub transport: String,
    pub claim_values: Vec<CredentialRequestClaimDTO>,
    pub redirect_uri: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SuspendCredentialRequestDTO {
    pub suspend_end_date: Option<OffsetDateTime>,
}

#[derive(Clone, Debug)]
pub struct CredentialRequestClaimDTO {
    pub claim_schema_id: ClaimSchemaId,
    pub value: String,
}

#[derive(Clone, Debug)]
pub struct CredentialRevocationCheckResponseDTO {
    pub credential_id: CredentialId,
    pub status: CredentialStateEnum,
    pub success: bool,
    pub reason: Option<String>,
}
