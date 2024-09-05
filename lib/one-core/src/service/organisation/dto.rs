use dto_mapper::From;
use shared_types::OrganisationId;
use time::OffsetDateTime;

use crate::model::organisation::Organisation;

#[derive(Clone, Debug, PartialEq, Eq, From)]
#[from(Organisation)]
pub struct GetOrganisationDetailsResponseDTO {
    pub id: OrganisationId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
}
