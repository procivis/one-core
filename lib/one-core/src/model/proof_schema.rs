use time::OffsetDateTime;
use uuid::Uuid;

use super::{
    claim_schema::ClaimSchema,
    common::{GetListQueryParams, GetListResponse},
    credential_schema::{CredentialSchema, CredentialSchemaRelations},
    organisation::{Organisation, OrganisationRelations},
};

pub type ProofSchemaId = Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofSchema {
    pub id: ProofSchemaId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
    pub name: String,
    pub expire_duration: u32,

    // Relations
    pub claim_schemas: Option<Vec<ProofSchemaClaim>>,
    pub organisation: Option<Organisation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofSchemaClaim {
    pub schema: ClaimSchema,
    pub required: bool,

    // Relations
    pub credential_schema: Option<CredentialSchema>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableProofSchemaColumn {
    Name,
    CreatedDate,
}

pub type GetProofSchemaList = GetListResponse<ProofSchema>;
pub type GetProofSchemaQuery = GetListQueryParams<SortableProofSchemaColumn>;

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct ProofSchemaClaimRelations {
    pub credential_schema: Option<CredentialSchemaRelations>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct ProofSchemaRelations {
    pub claim_schemas: Option<ProofSchemaClaimRelations>,
    pub organisation: Option<OrganisationRelations>,
}
