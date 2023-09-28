use crate::model::organisation::OrganisationId;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetOrganisationDetailsResponseDTO {
    pub id: OrganisationId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
}
