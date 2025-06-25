use shared_types::OrganisationId;
use time::OffsetDateTime;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Organisation {
    pub id: OrganisationId,
    pub name: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deactivated_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateOrganisationRequest {
    pub id: OrganisationId,
    pub name: String,
    pub deactivate: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct OrganisationRelations {}
