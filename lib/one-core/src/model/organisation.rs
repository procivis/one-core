use shared_types::{IdentifierId, OrganisationId};
use time::OffsetDateTime;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Organisation {
    pub id: OrganisationId,
    pub name: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deactivated_at: Option<OffsetDateTime>,
    pub wallet_provider: Option<String>,
    pub wallet_provider_issuer: Option<IdentifierId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateOrganisationRequest {
    pub id: OrganisationId,
    pub name: Option<String>,
    pub deactivate: Option<bool>,
    pub wallet_provider: Option<Option<String>>,
    pub wallet_provider_issuer: Option<Option<IdentifierId>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct OrganisationRelations {}
