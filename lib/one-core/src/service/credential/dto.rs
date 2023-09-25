use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::{
    common::{GetListQueryParams, GetListResponse},
    credential::{CredentialId, SortableCredentialColumn},
    credential_schema::CredentialSchemaId,
    organisation::OrganisationId,
};
use crate::service::credential_schema::dto::CredentialClaimSchemaDTO;

#[derive(Clone, Debug)]
pub struct CredentialListItemResponseDTO {
    pub id: CredentialId,
    pub created_date: OffsetDateTime,
    pub issuance_date: OffsetDateTime,
    pub state: CredentialStateEnum,
    pub last_modified: OffsetDateTime,
    pub schema: CredentialSchemaResponseDTO,
    pub issuer_did: Option<String>,
    pub credential: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CredentialResponseDTO {
    pub id: CredentialId,
    pub created_date: OffsetDateTime,
    pub issuance_date: OffsetDateTime,
    pub state: CredentialStateEnum,
    pub last_modified: OffsetDateTime,
    pub schema: CredentialSchemaResponseDTO,
    pub issuer_did: Option<String>,
    pub claims: Vec<DetailCredentialClaimResponseDTO>,
    pub credential: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CredentialSchemaResponseDTO {
    pub id: CredentialSchemaId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: String,
    pub revocation_method: String,
    pub organisation_id: OrganisationId,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DetailCredentialClaimResponseDTO {
    pub schema: CredentialClaimSchemaDTO,
    pub value: String,
}

#[derive(Debug, PartialEq, Clone, Deserialize)]
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

#[derive(Clone, Debug)]
pub struct EntityShareResponseDTO {
    pub credential_id: String,
    pub transport: String,
}
