use crate::model::revocation_list::RevocationListRelations;
use shared_types::DidId;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{
    claim::{Claim, ClaimRelations},
    common::{GetListQueryParams, GetListResponse},
    credential_schema::{CredentialSchema, CredentialSchemaRelations},
    did::{Did, DidRelations},
    interaction::{Interaction, InteractionId, InteractionRelations},
    key::{Key, KeyId, KeyRelations},
    revocation_list::RevocationList,
};

pub type CredentialId = Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Credential {
    pub id: CredentialId,
    pub created_date: OffsetDateTime,
    pub issuance_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub credential: Vec<u8>,
    pub transport: String,
    pub redirect_uri: Option<String>,

    // Relations:
    pub state: Option<Vec<CredentialState>>,
    pub claims: Option<Vec<Claim>>,
    pub issuer_did: Option<Did>,
    pub holder_did: Option<Did>,
    pub schema: Option<CredentialSchema>,
    pub interaction: Option<Interaction>,
    pub revocation_list: Option<RevocationList>,
    pub key: Option<Key>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct CredentialRelations {
    pub state: Option<CredentialStateRelations>,
    pub claims: Option<ClaimRelations>,
    pub issuer_did: Option<DidRelations>,
    pub holder_did: Option<DidRelations>,
    pub schema: Option<CredentialSchemaRelations>,
    pub interaction: Option<InteractionRelations>,
    pub revocation_list: Option<RevocationListRelations>,
    pub key: Option<KeyRelations>,
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

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct UpdateCredentialRequest {
    pub id: CredentialId,

    pub credential: Option<Vec<u8>>,
    pub holder_did_id: Option<DidId>,
    pub issuer_did_id: Option<DidId>,
    pub state: Option<CredentialState>,
    pub interaction: Option<InteractionId>,
    pub key: Option<KeyId>,
    pub redirect_uri: Option<Option<String>>,
}
