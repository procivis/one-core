use time::OffsetDateTime;
use uuid::Uuid;

pub type OrganisationId = Uuid;

pub struct Organisation {
    pub id: OrganisationId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
}
