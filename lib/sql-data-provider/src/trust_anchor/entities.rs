use one_core::service::trust_anchor::dto::TrustAnchorsListItemResponseDTO;
use one_dto_mapper::Into;
use sea_orm::FromQueryResult;
use shared_types::TrustAnchorId;
use time::OffsetDateTime;

#[derive(Debug, FromQueryResult, Into)]
#[into(TrustAnchorsListItemResponseDTO)]
pub(super) struct TrustAnchorsListItemEntityModel {
    pub id: TrustAnchorId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub r#type: String,
    pub publisher_reference: String,
    pub is_publisher: bool,
    pub entities: u32,
}
