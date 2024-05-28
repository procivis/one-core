use shared_types::TrustAnchorId;
use time::OffsetDateTime;

use super::organisation::{Organisation, OrganisationRelations};

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

    // Relations
    pub organisation: Option<Organisation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustAnchorRole {
    Publisher,
    Client,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct TrustAnchorRelations {
    pub organisation: Option<OrganisationRelations>,
}
