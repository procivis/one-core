use shared_types::{TrustAnchorId, TrustEntityId};
use time::OffsetDateTime;

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
    pub trust_anchor_id: TrustAnchorId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustEntityRole {
    Issuer,
    Verifier,
    Both,
}
