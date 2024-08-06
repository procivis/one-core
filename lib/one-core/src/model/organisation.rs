use dto_mapper::{From, Into};
use shared_types::OrganisationId;
use time::OffsetDateTime;

#[derive(Clone, Debug, Eq, PartialEq, From, Into)]
#[from(one_providers::common_models::organisation::OpenOrganisation)]
#[into(one_providers::common_models::organisation::OpenOrganisation)]
pub struct Organisation {
    pub id: OrganisationId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct OrganisationRelations {}
