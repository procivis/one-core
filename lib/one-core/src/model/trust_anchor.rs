use shared_types::{OrganisationId, TrustAnchorId};
use time::OffsetDateTime;

#[derive(Clone, Debug)]
pub struct TrustAnchor {
    pub id: TrustAnchorId,
    pub name: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub type_field: String,
    pub publisher_reference: Option<String>,
    pub role: TrustAnchorRole,
    pub priority: Option<u32>,
    pub organisation_id: OrganisationId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustAnchorRole {
    Publisher,
    Client,
}
