use dto_mapper::Into;
use one_core::service::trust_anchor::dto::TrustAnchorsListItemResponseDTO;
use sea_orm::FromQueryResult;
use shared_types::{OrganisationId, TrustAnchorId};
use time::OffsetDateTime;

use crate::entity::trust_anchor::TrustAnchorRole;

#[derive(FromQueryResult, Into)]
#[into(TrustAnchorsListItemResponseDTO)]
pub(super) struct TrustAnchorsListItemEntityModel {
    pub id: TrustAnchorId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub r#type: String,
    pub publisher_reference: Option<String>,
    pub role: TrustAnchorRole,
    pub priority: u32,
    pub organisation_id: OrganisationId,
    pub entities: u32,
}
