use shared_types::TrustAnchorId;
use time::OffsetDateTime;

#[derive(Clone, Debug)]
pub struct TrustAnchor {
    pub id: TrustAnchorId,
    pub name: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub r#type: String,
    pub publisher_reference: String,
    pub is_publisher: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct TrustAnchorRelations {}
