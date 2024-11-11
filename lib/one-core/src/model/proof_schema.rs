use shared_types::ProofSchemaId;
use time::OffsetDateTime;

use super::claim_schema::ClaimSchema;
use super::common::GetListResponse;
use super::credential_schema::{CredentialSchema, CredentialSchemaRelations};
use super::list_query::ListQuery;
use super::organisation::{Organisation, OrganisationRelations};
use crate::service::proof_schema::dto::ProofSchemaFilterValue;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofSchema {
    pub id: ProofSchemaId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
    pub name: String,
    pub expire_duration: u32,
    pub imported_source_url: Option<String>,

    // Relations
    pub organisation: Option<Organisation>,
    pub input_schemas: Option<Vec<ProofInputSchema>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct ProofInputSchema {
    pub validity_constraint: Option<i64>,

    // Relations
    pub claim_schemas: Option<Vec<ProofInputClaimSchema>>,
    pub credential_schema: Option<CredentialSchema>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofInputClaimSchema {
    pub schema: ClaimSchema,
    pub required: bool,
    pub order: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableProofSchemaColumn {
    Name,
    CreatedDate,
}

pub type GetProofSchemaList = GetListResponse<ProofSchema>;
pub type GetProofSchemaQuery = ListQuery<SortableProofSchemaColumn, ProofSchemaFilterValue>;

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct ProofSchemaRelations {
    pub organisation: Option<OrganisationRelations>,
    pub proof_inputs: Option<ProofInputSchemaRelations>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct ProofSchemaClaimRelations {}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct ProofInputSchemaRelations {
    pub claim_schemas: Option<ProofSchemaClaimRelations>,
    pub credential_schema: Option<CredentialSchemaRelations>,
}
