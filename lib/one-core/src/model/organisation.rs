use dto_mapper::{From, Into};
use shared_types::OrganisationId;
use time::OffsetDateTime;

use super::relation::Model;

#[derive(Clone, Debug, Eq, PartialEq, From, Into)]
#[from(one_providers::common_models::organisation::OpenOrganisation)]
#[into(one_providers::common_models::organisation::OpenOrganisation)]
pub struct Organisation {
    pub id: OrganisationId,
    #[from(replace = OffsetDateTime::now_utc())]
    #[into(skip)]
    pub created_date: OffsetDateTime,
    #[from(replace = OffsetDateTime::now_utc())]
    #[into(skip)]
    pub last_modified: OffsetDateTime,
}

impl Model for Organisation {
    type Id = OrganisationId;
    fn id(&self) -> &Self::Id {
        &self.id
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct OrganisationRelations {}
