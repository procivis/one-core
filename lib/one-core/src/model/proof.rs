use super::{
    claim::{Claim, ClaimRelations},
    common::{GetListQueryParams, GetListResponse},
    did::{Did, DidRelations},
    proof_schema::{ProofSchema, ProofSchemaRelations},
};
use time::OffsetDateTime;
use uuid::Uuid;

pub type ProofId = Uuid;
pub type ProofClaimId = Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof {
    pub id: ProofId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub issuance_date: OffsetDateTime,
    pub transport: String,

    // Relations
    pub state: Option<Vec<ProofState>>,
    pub schema: Option<ProofSchema>,
    pub claims: Option<Vec<Claim>>,
    pub verifier_did: Option<Did>,
    pub holder_did: Option<Did>, // empty either because relation not specified or not set in database
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProofStateEnum {
    Created,
    Pending,
    Offered,
    Accepted,
    Rejected,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofState {
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub state: ProofStateEnum,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableProofColumn {
    SchemaName,
    VerifierDid,
    State,
    CreatedDate,
}

pub type GetProofList = GetListResponse<Proof>;
pub type GetProofQuery = GetListQueryParams<SortableProofColumn>;

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct ProofRelations {
    pub state: Option<ProofStateRelations>,
    pub claims: Option<ClaimRelations>,
    pub schema: Option<ProofSchemaRelations>,
    pub verifier_did: Option<DidRelations>,
    pub holder_did: Option<DidRelations>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct ProofStateRelations {}
