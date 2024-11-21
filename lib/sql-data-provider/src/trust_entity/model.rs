use sea_orm::FromQueryResult;
use shared_types::{DidId, TrustAnchorId, TrustEntityId};
use time::OffsetDateTime;

use crate::entity::trust_entity::{TrustEntityRole, TrustEntityState};

#[derive(FromQueryResult)]
pub(super) struct TrustEntityListItemEntityModel {
    pub id: TrustEntityId,
    pub name: String,

    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,

    pub logo: Option<Vec<u8>>,
    pub website: Option<String>,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    pub role: TrustEntityRole,
    pub state: TrustEntityState,
    pub trust_anchor_id: TrustAnchorId,
    pub did_id: DidId,
}
