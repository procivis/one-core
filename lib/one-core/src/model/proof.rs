use serde::Serialize;
use shared_types::{BlobId, EcosystemId, IdentifierId, InteractionId, ProofId};
use strum::Display;
use time::OffsetDateTime;

use super::certificate::Certificate;
use super::claim::Claim;
use super::common::GetListResponse;
use super::credential::Credential;
use super::identifier::Identifier;
use super::interaction::Interaction;
use super::key::Key;
use super::list_query::ListQuery;
use super::proof_schema::ProofSchema;
use crate::model::relation::{Related, RelatedVec};
use crate::service::proof::dto::ProofFilterValue;

#[derive(Clone, Debug)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
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
    pub webhook_url: Option<String>,
    pub subscriber_information: Option<String>,
    pub ecosystem: Option<EcosystemId>,

    // Relations
    pub schema: Option<Related<ProofSchema>>,
    pub claims: RelatedVec<ProofClaim>,
    pub verifier_identifier: Option<Related<Identifier>>,
    pub verifier_certificate: Option<Related<Certificate>>,
    pub verifier_key: Option<Related<Key>>,
    pub interaction: Option<Related<Interaction>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Display, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProofStateEnum {
    Created,
    Pending,
    Requested,
    Accepted,
    Rejected,
    Retracted,
    Error,
    InteractionExpired,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Display)]
pub enum ProofRole {
    Holder,
    Verifier,
}

#[derive(Clone, Debug)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct ProofClaim {
    pub claim: Claim,

    // Relations
    pub credential: Related<Credential>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableProofColumn {
    SchemaName,
    Verifier,
    State,
    CreatedDate,
}

pub type GetProofList<Count = Option<u64>> = GetListResponse<Proof, Count>;
pub type ProofListQuery = ListQuery<SortableProofColumn, ProofFilterValue>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExactProofFilterColumn {
    Name,
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
    pub ecosystem: Option<Option<EcosystemId>>,
}
