use time::OffsetDateTime;
use uuid::Uuid;

pub type OrganisationId = Uuid;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetOrganisationDetailsResponseDTO {
    pub id: OrganisationId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
}
