use std::str::FromStr;

use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;

use dto_mapper::{From, TryFrom};

use crate::{
    model::{
        claim_schema::ClaimSchemaId,
        common::{GetListQueryParams, GetListResponse},
        credential_schema::{
            CredentialFormat, CredentialSchema, CredentialSchemaId, RevocationMethod,
            SortableCredentialSchemaColumn,
        },
        organisation::OrganisationId,
    },
    provider::transport_protocol::dto::ProofCredentialSchema,
    service::error::ServiceError,
};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, From, TryFrom)]
#[from(CredentialSchema)]
#[try_from(T = ProofCredentialSchema, Error = ServiceError)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchemaListItemResponseDTO {
    #[try_from(with_fn_ref = "uuid::Uuid::from_str")]
    pub id: CredentialSchemaId,
    #[try_from(infallible)]
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[try_from(infallible)]
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    #[try_from(infallible)]
    pub name: String,
    #[try_from(infallible)]
    pub format: CredentialFormat,
    #[try_from(infallible)]
    pub revocation_method: RevocationMethod,
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
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
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
}

pub type GetCredentialSchemaListResponseDTO = GetListResponse<CredentialSchemaListItemResponseDTO>;
pub type GetCredentialSchemaQueryDTO = GetListQueryParams<SortableCredentialSchemaColumn>;

#[derive(Clone, Debug)]
pub struct CreateCredentialSchemaRequestDTO {
    pub name: String,
    pub format: String,
    pub revocation_method: String,
    pub organisation_id: Uuid,
    pub claims: Vec<CredentialClaimSchemaRequestDTO>,
}

#[derive(Clone, Debug)]
pub struct CredentialClaimSchemaRequestDTO {
    pub key: String,
    pub datatype: String,
    pub required: bool,
}
