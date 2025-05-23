use one_dto_mapper::{From, Into};
use shared_types::OrganisationId;
use time::OffsetDateTime;

use crate::model::organisation::{Organisation, UpdateOrganisationRequest};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CreateOrganisationRequestDTO {
    pub id: Option<OrganisationId>,
    pub name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Into)]
#[into(UpdateOrganisationRequest)]
pub struct UpsertOrganisationRequestDTO {
    pub id: OrganisationId,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, From)]
#[from(Organisation)]
pub struct GetOrganisationDetailsResponseDTO {
    pub id: OrganisationId,
    pub name: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
}
