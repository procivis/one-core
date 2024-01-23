use time::OffsetDateTime;

use dto_mapper::From;

use crate::model::organisation::{Organisation, OrganisationId};

#[derive(Clone, Debug, PartialEq, Eq, From)]
#[from(Organisation)]
pub struct GetOrganisationDetailsResponseDTO {
    pub id: OrganisationId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
}
