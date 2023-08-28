use time::OffsetDateTime;
use uuid::Uuid;

use super::did::{Did, DidRelations};

pub type OrganisationId = Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Organisation {
    pub id: OrganisationId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,

    // Relations
    pub did: Option<Vec<Did>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct OrganisationRelations {
    pub did: Option<DidRelations>,
}
