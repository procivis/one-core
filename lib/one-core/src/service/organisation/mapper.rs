use crate::model::organisation::Organisation;

use super::dto::GetOrganisationDetailsResponseDTO;

impl From<Organisation> for GetOrganisationDetailsResponseDTO {
    fn from(value: Organisation) -> Self {
        GetOrganisationDetailsResponseDTO {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
        }
    }
}
