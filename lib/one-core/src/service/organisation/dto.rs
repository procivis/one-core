use one_dto_mapper::{From, Into};
use shared_types::{IdentifierId, OrganisationId};
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
    pub name: Option<String>,
    pub deactivate: Option<bool>,
    pub wallet_provider: Option<Option<String>>,
    pub wallet_provider_issuer: Option<Option<IdentifierId>>,
}

#[derive(Clone, Debug, PartialEq, Eq, From)]
#[from(Organisation)]
pub struct GetOrganisationDetailsResponseDTO {
    pub id: OrganisationId,
    pub name: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deactivated_at: Option<OffsetDateTime>,
    pub wallet_provider: Option<String>,
    pub wallet_provider_issuer: Option<IdentifierId>,
}
