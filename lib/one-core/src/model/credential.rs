use crate::model::common::{GetListQueryParams, GetListResponse};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{
    claim::{Claim, ClaimRelations},
    credential_schema::{CredentialSchema, CredentialSchemaRelations},
    did::{Did, DidRelations},
};

pub type CredentialId = Uuid;

#[derive(Clone)]
pub struct Credential {
    pub id: CredentialId,
    pub created_date: OffsetDateTime,
    pub issuance_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub credential: Vec<u8>,
    pub transport: String,

    // Relations:
    pub state: Option<Vec<CredentialState>>,
    pub claims: Option<Vec<Claim>>,
    pub issuer_did: Option<Did>,
    pub receiver_did: Option<Did>,
    pub schema: Option<CredentialSchema>,
}

#[derive(Default)]
pub struct CredentialRelations {
    pub state: Option<CredentialStateRelations>,
    pub claims: Option<ClaimRelations>,
    pub issuer_did: Option<DidRelations>,
    pub receiver_did: Option<DidRelations>,
    pub schema: Option<CredentialSchemaRelations>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialState {
    pub created_date: OffsetDateTime,
    pub state: CredentialStateEnum,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialStateEnum {
    Created,
    Pending,
    Offered,
    Accepted,
    Rejected,
    Revoked,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct CredentialStateRelations {}

pub enum SortableCredentialColumn {
    CreatedDate,
    SchemaName,
    IssuerDid,
    State,
}

pub type GetCredentialList = GetListResponse<Credential>;
pub type GetCredentialQuery = GetListQueryParams<SortableCredentialColumn>;
