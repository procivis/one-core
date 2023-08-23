use one_core::service::organisation::dto::GetOrganisationDetailsResponseDTO;
use uuid::Uuid;

use super::dto::{CreateOrganisationResponseRestDTO, GetOrganisationDetailsResponseRestDTO};

impl From<Uuid> for CreateOrganisationResponseRestDTO {
    fn from(value: Uuid) -> Self {
        Self { id: value }
    }
}

impl From<GetOrganisationDetailsResponseDTO> for GetOrganisationDetailsResponseRestDTO {
    fn from(value: GetOrganisationDetailsResponseDTO) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
        }
    }
}
