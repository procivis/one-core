use sea_orm::FromQueryResult;
use shared_types::{DidId, DidValue, TrustAnchorId, TrustEntityId};
use time::OffsetDateTime;

use crate::entity::did::DidType;
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

    // Trust Anchor relation
    pub trust_anchor_id: TrustAnchorId,
    pub trust_anchor_name: String,
    pub trust_anchor_created_date: OffsetDateTime,
    pub trust_anchor_last_modified: OffsetDateTime,
    pub trust_anchor_type: String,
    pub trust_anchor_publisher_reference: String,
    pub trust_anchor_is_publisher: bool,

    // DID relation
    pub did_id: DidId,
    pub did: DidValue,
    pub did_created_date: OffsetDateTime,
    pub did_last_modified: OffsetDateTime,
    pub did_name: String,
    pub did_type: DidType,
    pub did_method: String,
    pub did_deactivated: bool,
}
