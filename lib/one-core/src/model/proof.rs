use shared_types::{BlobId, IdentifierId, ProofId};
use strum::Display;
use time::OffsetDateTime;

use super::certificate::{Certificate, CertificateRelations};
use super::claim::{Claim, ClaimRelations};
use super::common::GetListResponse;
use super::credential::{Credential, CredentialRelations};
use super::identifier::{Identifier, IdentifierRelations};
use super::interaction::{Interaction, InteractionId, InteractionRelations};
use super::key::Key;
use super::list_query::ListQuery;
use super::proof_schema::{ProofSchema, ProofSchemaRelations};
use crate::model::key::KeyRelations;
use crate::service::proof::dto::ProofFilterValue;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof {
    pub id: ProofId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub protocol: String,
    pub transport: String,
    pub redirect_uri: Option<String>,
    pub state: ProofStateEnum,
    pub role: ProofRole,
    pub requested_date: Option<OffsetDateTime>,
    pub completed_date: Option<OffsetDateTime>,
    pub profile: Option<String>,
    pub proof_blob_id: Option<BlobId>,
    pub engagement: Option<String>,

    // Relations
    pub schema: Option<ProofSchema>,
    pub claims: Option<Vec<ProofClaim>>,
    pub verifier_identifier: Option<Identifier>,
    pub verifier_certificate: Option<Certificate>,
    pub verifier_key: Option<Key>,
    pub interaction: Option<Interaction>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Display)]
pub enum ProofStateEnum {
    Created,
    Pending,
    Requested,
    Accepted,
    Rejected,
    Retracted,
    Error,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Display)]
pub enum ProofRole {
    Holder,
    Verifier,
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
    Verifier,
    State,
    CreatedDate,
}

pub type GetProofList = GetListResponse<Proof>;
pub type GetProofQuery = ListQuery<SortableProofColumn, ProofFilterValue>;

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct ProofRelations {
    pub schema: Option<ProofSchemaRelations>,
    pub claims: Option<ProofClaimRelations>,
    pub verifier_identifier: Option<IdentifierRelations>,
    pub verifier_key: Option<KeyRelations>,
    pub verifier_certificate: Option<CertificateRelations>,
    pub interaction: Option<InteractionRelations>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct ProofClaimRelations {
    pub claim: ClaimRelations,
    pub credential: Option<CredentialRelations>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct UpdateProofRequest {
    pub verifier_identifier_id: Option<IdentifierId>,
    pub state: Option<ProofStateEnum>,
    pub interaction: Option<Option<InteractionId>>,
    pub redirect_uri: Option<Option<String>>,
    pub transport: Option<String>,
    pub requested_date: Option<Option<OffsetDateTime>>,
    pub proof_blob_id: Option<Option<BlobId>>,
    pub engagement: Option<Option<String>>,
}
