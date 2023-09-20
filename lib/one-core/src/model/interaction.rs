use time::OffsetDateTime;
use uuid::Uuid;

pub type InteractionId = Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Interaction {
    pub id: InteractionId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub host: Option<String>,
    pub data: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct InteractionRelations {}
