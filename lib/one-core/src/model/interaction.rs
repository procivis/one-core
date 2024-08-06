use dto_mapper::{From, Into};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

pub type InteractionId = Uuid;

#[derive(Clone, Debug, Eq, PartialEq, From, Into)]
#[from(one_providers::common_models::interaction::OpenInteraction)]
#[into(one_providers::common_models::interaction::OpenInteraction)]
pub struct Interaction {
    pub id: InteractionId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub host: Option<Url>, // base URL like: `https://core.dev.one-trust-solution.com`
    pub data: Option<Vec<u8>>, // empty for credential offer, json-serialized `Vec<ProofClaimSchema>` for proof request
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct InteractionRelations {}
