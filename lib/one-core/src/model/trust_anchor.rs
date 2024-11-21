use shared_types::TrustAnchorId;
use time::OffsetDateTime;

#[derive(Clone, Debug)]
pub struct TrustAnchor {
    pub id: TrustAnchorId,
    pub name: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub type_field: String,
    pub publisher_reference: Option<String>,
    pub role: TrustAnchorRole,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustAnchorRole {
    Publisher,
    Client,
}

impl TrustAnchorRole {
    pub fn is_publisher(&self) -> bool {
        matches!(self, Self::Publisher)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct TrustAnchorRelations {}
