use shared_types::OrganisationId;
use time::OffsetDateTime;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Organisation {
    pub id: OrganisationId,
    pub name: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct OrganisationRelations {}
