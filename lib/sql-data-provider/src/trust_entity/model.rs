use sea_orm::FromQueryResult;
use shared_types::{DidId, DidValue, OrganisationId, TrustAnchorId, TrustEntityId};
use time::OffsetDateTime;

use crate::entity::did::DidType;
use crate::entity::trust_entity::{TrustEntityRole, TrustEntityState, TrustEntityType};

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
    #[sea_orm(from_col = "type")]
    pub r#type: TrustEntityType,
    pub entity_key: String,
    #[allow(unused)]
    pub content: Option<Vec<u8>>,
    pub organisation_id: Option<OrganisationId>,

    // Trust Anchor relation
    pub trust_anchor_id: TrustAnchorId,
    pub trust_anchor_name: String,
    pub trust_anchor_created_date: OffsetDateTime,
    pub trust_anchor_last_modified: OffsetDateTime,
    pub trust_anchor_type: String,
    pub trust_anchor_publisher_reference: String,
    pub trust_anchor_is_publisher: bool,

    // DID relation
    pub did_id: Option<DidId>,
    pub did: Option<DidValue>,
    pub did_created_date: Option<OffsetDateTime>,
    pub did_last_modified: Option<OffsetDateTime>,
    pub did_name: Option<String>,
    pub did_type: Option<DidType>,
    pub did_method: Option<String>,
    pub did_deactivated: Option<bool>,
}
