use time::OffsetDateTime;
use uuid::Uuid;

use super::claim_schema::{ClaimSchema, ClaimSchemaRelations};
use super::common::{GetListQueryParams, GetListResponse};
use super::organisation::{Organisation, OrganisationRelations};

pub type CredentialSchemaId = Uuid;
pub type Name = String;
pub type Format = String;
pub type RevocationMethod = String;
pub type OrganisationId = Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialSchema {
    pub id: CredentialSchemaId,
    pub deleted_at: Option<OffsetDateTime>,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: Name,
    pub format: Format,
    pub revocation_method: RevocationMethod,

    // Relations
    pub claim_schemas: Option<Vec<ClaimSchema>>,
    pub organisation: Option<Organisation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct CredentialSchemaRelations {
    pub claim_schema: Option<ClaimSchemaRelations>,
    pub organisation: Option<OrganisationRelations>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableCredentialSchemaColumn {
    Name,
    Format,
    CreatedDate,
}

pub type GetCredentialSchemaList = GetListResponse<CredentialSchema>;
pub type GetCredentialSchemaQuery = GetListQueryParams<SortableCredentialSchemaColumn>;
