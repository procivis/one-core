use shared_types::TrustEntityId;
use time::OffsetDateTime;

use super::trust_anchor::{TrustAnchor, TrustAnchorRelations};

#[derive(Clone, Debug)]
pub struct TrustEntity {
    pub id: TrustEntityId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub entity_id: String,
    pub name: String,
    pub logo: Option<String>,
    pub website: Option<String>,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    pub role: TrustEntityRole,

    // Relations
    pub trust_anchor: Option<TrustAnchor>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustEntityRole {
    Issuer,
    Verifier,
    Both,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct TrustEntityRelations {
    pub trust_anchor: Option<TrustAnchorRelations>,
}
