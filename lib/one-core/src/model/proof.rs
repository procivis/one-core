use strum_macros::Display;
use time::OffsetDateTime;
use uuid::Uuid;

use shared_types::DidId;

use super::{
    claim::{Claim, ClaimRelations},
    common::{GetListQueryParams, GetListResponse},
    credential::{Credential, CredentialRelations},
    did::{Did, DidRelations},
    interaction::{Interaction, InteractionId, InteractionRelations},
    key::{Key, KeyRelations},
    proof_schema::{ProofSchema, ProofSchemaRelations},
};

pub type ProofId = Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof {
    pub id: ProofId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub issuance_date: OffsetDateTime,
    pub transport: String,
    pub redirect_uri: Option<String>,

    // Relations
    pub state: Option<Vec<ProofState>>,
    pub schema: Option<ProofSchema>,
    pub claims: Option<Vec<ProofClaim>>,
    pub verifier_did: Option<Did>,
    pub holder_did: Option<Did>, // empty either because relation not specified or not set in database
    pub verifier_key: Option<Key>,
    pub interaction: Option<Interaction>,
}

#[derive(Clone, Debug, Eq, PartialEq, Display)]
pub enum ProofStateEnum {
    Created,
    Pending,
    Requested,
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
pub struct ProofClaim {
    pub claim: Claim,

    // Relations
    pub credential: Option<Credential>,
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
    pub schema: Option<ProofSchemaRelations>,
    pub claims: Option<ProofClaimRelations>,
    pub verifier_did: Option<DidRelations>,
    pub holder_did: Option<DidRelations>,
    pub verifier_key: Option<KeyRelations>,
    pub interaction: Option<InteractionRelations>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct ProofStateRelations {}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct ProofClaimRelations {
    pub claim: ClaimRelations,
    pub credential: Option<CredentialRelations>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct UpdateProofRequest {
    pub id: ProofId,

    pub holder_did_id: Option<DidId>,
    pub verifier_did_id: Option<DidId>,
    pub state: Option<ProofState>,
    pub interaction: Option<InteractionId>,
    pub redirect_uri: Option<Option<String>>,
}
