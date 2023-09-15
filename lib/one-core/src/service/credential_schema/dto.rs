use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::common::{GetListQueryParams, GetListResponse};
use crate::model::credential_schema::SortableCredentialSchemaColumn;
use crate::service::organisation::dto::OrganisationId;

pub type ClaimSchemaId = Uuid;
pub type CredentialSchemaId = Uuid;
pub type Format = String;
pub type RevocationMethod = String;
pub type Key = String;
pub type Datatype = String;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetCredentialSchemaListValueResponseDTO {
    pub id: CredentialSchemaId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: Format,
    pub revocation_method: RevocationMethod,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetCredentialSchemaResponseDTO {
    pub id: CredentialSchemaId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: Format,
    pub revocation_method: RevocationMethod,
    pub organisation_id: OrganisationId,
    pub claims: Vec<CredentialClaimSchemaDTO>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialClaimSchemaDTO {
    pub id: ClaimSchemaId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub key: Key,
    pub datatype: Datatype,
    pub required: bool,
}

pub type GetCredentialSchemaListResponseDTO =
    GetListResponse<GetCredentialSchemaListValueResponseDTO>;
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
pub struct CreateCredentialSchemaResponseDTO {
    pub id: Uuid,
}

#[derive(Clone, Debug)]
pub struct CredentialClaimSchemaRequestDTO {
    pub key: String,
    pub datatype: String,
    pub required: bool,
}
