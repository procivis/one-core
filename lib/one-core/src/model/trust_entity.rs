use shared_types::TrustEntityId;
use time::OffsetDateTime;

use super::did::{Did, DidRelations};
use super::trust_anchor::{TrustAnchor, TrustAnchorRelations};

#[derive(Clone, Debug)]
pub struct TrustEntity {
    pub id: TrustEntityId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub logo: Option<String>,
    pub website: Option<String>,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    pub role: TrustEntityRole,
    pub state: TrustEntityState,

    // Relations
    pub trust_anchor: Option<TrustAnchor>,
    pub did: Option<Did>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustEntityRole {
    Issuer,
    Verifier,
    Both,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustEntityState {
    Active,
    Removed,
    Withdrawn,
    RemovedAndWithdrawn,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct TrustEntityRelations {
    pub trust_anchor: Option<TrustAnchorRelations>,
    pub did: Option<DidRelations>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UpdateTrustEntityRequest {
    pub state: Option<TrustEntityState>,
    pub logo: Option<Option<String>>,
    pub privacy_url: Option<Option<String>>,
    pub website: Option<Option<String>>,
    pub name: Option<String>,
    pub terms_url: Option<Option<String>>,
    pub role: Option<TrustEntityRole>,
}
