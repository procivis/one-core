use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    model::{
        common::{GetListQueryParams, GetListResponse},
        credential::{CredentialId, SortableCredentialColumn},
        credential_schema::{CredentialFormat, CredentialSchemaId, RevocationMethod},
        organisation::OrganisationId,
    },
    service::credential_schema::dto::{
        CredentialClaimSchemaDTO, CredentialSchemaListItemResponseDTO,
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
    pub issuer_did: Option<String>,
    pub credential: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialDetailResponseDTO {
    pub id: CredentialId,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub issuance_date: OffsetDateTime,
    #[serde(with = "time::serde::timestamp::option")]
    pub revocation_date: Option<OffsetDateTime>,
    pub state: CredentialStateEnum,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub schema: DetailCredentialSchemaResponseDTO,
    pub issuer_did: Option<String>,
    pub claims: Vec<DetailCredentialClaimResponseDTO>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetailCredentialSchemaResponseDTO {
    pub id: CredentialSchemaId,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: CredentialFormat,
    pub revocation_method: RevocationMethod,
    pub organisation_id: OrganisationId,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetailCredentialClaimResponseDTO {
    pub schema: CredentialClaimSchemaDTO,
    pub value: String,
}

#[derive(Debug, PartialEq, Clone, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CredentialStateEnum {
    Created,
    Pending,
    Offered,
    Accepted,
    Rejected,
    Revoked,
    Error,
}

pub type GetCredentialListResponseDTO = GetListResponse<CredentialListItemResponseDTO>;
pub type GetCredentialQueryDTO = GetListQueryParams<SortableCredentialColumn>;

#[derive(Clone, Debug)]
pub struct CreateCredentialRequestDTO {
    pub credential_schema_id: Uuid,
    pub issuer_did: Uuid,
    pub transport: String,
    pub claim_values: Vec<CredentialRequestClaimDTO>,
}

#[derive(Clone, Debug)]
pub struct CredentialRequestClaimDTO {
    pub claim_schema_id: Uuid,
    pub value: String,
}
