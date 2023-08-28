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

pub(crate) fn organisations_to_response(
    organisations: Vec<Organisation>,
) -> Vec<GetOrganisationDetailsResponseDTO> {
    organisations.into_iter().map(|v| v.into()).collect()
}
