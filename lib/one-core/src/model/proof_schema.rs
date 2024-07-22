use dto_mapper::{convert_inner, convert_inner_of_inner, Into};
use shared_types::ProofSchemaId;
use time::OffsetDateTime;

use super::{
    claim_schema::ClaimSchema,
    common::{GetListQueryParams, GetListResponse},
    credential_schema::{CredentialSchema, CredentialSchemaRelations},
    organisation::{Organisation, OrganisationRelations},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofSchema {
    pub id: ProofSchemaId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
    pub name: String,
    pub expire_duration: u32,

    // Relations
    pub organisation: Option<Organisation>,
    pub input_schemas: Option<Vec<ProofInputSchema>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default, Into)]
#[into(one_providers::common_models::proof_schema::ProofInputSchema)]
pub struct ProofInputSchema {
    pub validity_constraint: Option<i64>,

    // Relations
    #[into(with_fn = "convert_inner_of_inner")]
    pub claim_schemas: Option<Vec<ProofInputClaimSchema>>,
    #[into(with_fn = "convert_inner")]
    pub credential_schema: Option<CredentialSchema>,
}

#[derive(Clone, Debug, Eq, PartialEq, Into)]
#[into(one_providers::common_models::proof_schema::ProofInputClaimSchema)]
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
pub type GetProofSchemaQuery = GetListQueryParams<SortableProofSchemaColumn>;

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
