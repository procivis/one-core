use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

pub type InteractionId = Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Interaction {
    pub id: InteractionId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub host: Option<Url>, // base URL like: `https://core.dev.one-trust-solution.com`
    pub data: Option<Vec<u8>>, // empty for credential offer, json-serialized `Vec<ProofClaimSchema>` for proof request
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct InteractionRelations {}
