use dto_mapper::{convert_inner, convert_inner_of_inner, From, Into};
use one_providers::common_models::key::OpenKey;
use shared_types::{DidId, ProofId};
use strum_macros::Display;
use time::OffsetDateTime;

use super::claim::{Claim, ClaimRelations};
use super::common::GetListResponse;
use super::credential::{Credential, CredentialRelations};
use super::did::{Did, DidRelations};
use super::interaction::{Interaction, InteractionId, InteractionRelations};
use super::list_query::ListQuery;
use super::proof_schema::{ProofSchema, ProofSchemaRelations};
use crate::model::key::KeyRelations;
use crate::service::proof::dto::ProofFilterValue;

#[derive(Clone, Debug, Eq, PartialEq, Into, From)]
#[into(one_providers::common_models::proof::OpenProof)]
#[from(one_providers::common_models::proof::OpenProof)]
pub struct Proof {
    pub id: ProofId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub issuance_date: OffsetDateTime,
    pub exchange: String,
    pub transport: String,
    pub redirect_uri: Option<String>,

    // Relations
    #[into(with_fn = "convert_inner_of_inner")]
    #[from(with_fn = "convert_inner_of_inner")]
    pub state: Option<Vec<ProofState>>,
    #[into(with_fn = "convert_inner")]
    #[from(with_fn = "convert_inner")]
    pub schema: Option<ProofSchema>,
    #[into(with_fn = "convert_inner_of_inner")]
    #[from(with_fn = "convert_inner_of_inner")]
    pub claims: Option<Vec<ProofClaim>>,
    #[into(with_fn = "convert_inner")]
    #[from(with_fn = "convert_inner")]
    pub verifier_did: Option<Did>,
    #[into(with_fn = "convert_inner")]
    #[from(with_fn = "convert_inner")]
    pub holder_did: Option<Did>, // empty either because relation not specified or not set in database
    #[into(with_fn = "convert_inner")]
    #[from(with_fn = "convert_inner")]
    pub verifier_key: Option<OpenKey>,
    #[into(with_fn = "convert_inner")]
    #[from(with_fn = "convert_inner")]
    pub interaction: Option<Interaction>,
}

#[derive(Clone, Debug, Eq, PartialEq, Display, Into, From)]
#[into(one_providers::common_models::proof::OpenProofStateEnum)]
#[from(one_providers::common_models::proof::OpenProofStateEnum)]
pub enum ProofStateEnum {
    Created,
    Pending,
    Requested,
    Accepted,
    Rejected,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq, Into, From)]
#[into(one_providers::common_models::proof::OpenProofState)]
#[from(one_providers::common_models::proof::OpenProofState)]
pub struct ProofState {
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub state: ProofStateEnum,
}

#[derive(Clone, Debug, Eq, PartialEq, Into, From)]
#[into(one_providers::common_models::proof::OpenProofClaim)]
#[from(one_providers::common_models::proof::OpenProofClaim)]
pub struct ProofClaim {
    pub claim: Claim,

    // Relations
    #[into(with_fn = "convert_inner")]
    #[from(with_fn = "convert_inner")]
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
pub type GetProofQuery = ListQuery<SortableProofColumn, ProofFilterValue>;

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

#[derive(Clone, Debug, Default, Eq, PartialEq, From)]
#[from(one_providers::common_models::proof::OpenUpdateProofRequest)]
pub struct UpdateProofRequest {
    pub id: ProofId,

    #[from(with_fn = convert_inner)]
    pub holder_did_id: Option<DidId>,
    #[from(with_fn = convert_inner)]
    pub verifier_did_id: Option<DidId>,
    #[from(with_fn = convert_inner)]
    pub state: Option<ProofState>,
    #[from(with_fn = convert_inner_of_inner)]
    pub interaction: Option<Option<InteractionId>>,
    pub redirect_uri: Option<Option<String>>,
}
