use dto_mapper::From;
use shared_types::{CredentialId, DidId, KeyId, OrganisationId};
use strum_macros::Display;
use time::OffsetDateTime;

use super::claim::{Claim, ClaimRelations};
use super::common::GetListResponse;
use super::credential_schema::{CredentialSchema, CredentialSchemaRelations};
use super::did::{Did, DidRelations};
use super::interaction::{Interaction, InteractionId, InteractionRelations};
use super::key::{Key, KeyRelations};
use super::list_query::ListQuery;
use super::revocation_list::{RevocationList, RevocationListRelations};
use crate::service::credential::dto::{
    CredentialFilterValue, CredentialListIncludeEntityTypeEnum, GetCredentialQueryFiltersDTO,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Credential {
    pub id: CredentialId,
    pub created_date: OffsetDateTime,
    pub issuance_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
    pub credential: Vec<u8>,
    pub exchange: String,
    pub redirect_uri: Option<String>,
    pub role: CredentialRole,

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
    pub suspend_end_date: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Eq, PartialEq, Display)]
pub enum CredentialStateEnum {
    Created,
    Pending,
    Offered,
    Accepted,
    Rejected,
    Revoked,
    Suspended,
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
pub type GetCredentialQuery =
    ListQuery<SortableCredentialColumn, CredentialFilterValue, CredentialListIncludeEntityTypeEnum>;

#[derive(From)]
#[from(GetCredentialQueryFiltersDTO)]
pub struct GetCredentialQueryFilters {
    pub query: GetCredentialQuery,
    pub organisation_id: Option<OrganisationId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialRole {
    Holder,
    Issuer,
    Verifier,
}
