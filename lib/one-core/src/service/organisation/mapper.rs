use crate::{
    model::organisation::Organisation,
    service::organisation::dto::GetOrganisationDetailsResponseDTO,
};

pub(crate) fn organisations_to_response(
    organisations: Vec<Organisation>,
) -> Vec<GetOrganisationDetailsResponseDTO> {
    organisations.into_iter().map(|v| v.into()).collect()
}
