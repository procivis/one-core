use sea_orm::FromQueryResult;
use shared_types::{OrganisationId, TrustAnchorId, TrustEntityId};
use time::OffsetDateTime;

use crate::entity::trust_entity::TrustEntityRole;

#[derive(FromQueryResult)]
pub(super) struct TrustEntityListItemEntityModel {
    pub id: TrustEntityId,
    pub name: String,

    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,

    pub entity_id: String,
    pub logo: Option<Vec<u8>>,
    pub website: Option<String>,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    pub role: TrustEntityRole,
    pub trust_anchor_id: TrustAnchorId,
    pub organisation_id: OrganisationId,
}
