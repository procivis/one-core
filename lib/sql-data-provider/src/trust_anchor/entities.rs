use one_core::model::trust_anchor::TrustAnchorRole;
use one_core::service::trust_anchor::dto::TrustAnchorsListItemResponseDTO;
use sea_orm::FromQueryResult;
use shared_types::TrustAnchorId;
use time::OffsetDateTime;

#[derive(Debug, FromQueryResult)]
pub(super) struct TrustAnchorsListItemEntityModel {
    pub id: TrustAnchorId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub r#type: String,
    pub publisher_reference: Option<String>,
    pub is_publisher: bool,
    pub entities: u32,
}

impl From<TrustAnchorsListItemEntityModel> for TrustAnchorsListItemResponseDTO {
    fn from(value: TrustAnchorsListItemEntityModel) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            r#type: value.r#type,
            publisher_reference: value.publisher_reference,
            role: if value.is_publisher {
                TrustAnchorRole::Publisher
            } else {
                TrustAnchorRole::Client
            },
            entities: value.entities,
        }
    }
}
