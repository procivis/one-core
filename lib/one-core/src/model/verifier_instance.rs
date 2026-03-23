use shared_types::VerifierInstanceId;
use time::OffsetDateTime;

use crate::model::organisation::{Organisation, OrganisationRelations};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifierInstance {
    pub id: VerifierInstanceId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub provider_type: String,
    pub provider_name: String,
    pub provider_url: String,

    // Relations:
    pub organisation: Option<Organisation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct VerifierInstanceRelations {
    pub organisation: Option<OrganisationRelations>,
}
