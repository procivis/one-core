use one_dto_mapper::From;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use crate::model::organisation::{Organisation, OrganisationRelations};

pub type InteractionId = Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Interaction {
    pub id: InteractionId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub host: Option<Url>, // base URL like: `https://core.dev.one-trust-solution.com`
    pub data: Option<Vec<u8>>, // empty for credential offer, json-serialized `Vec<ProofClaimSchema>` for proof request
    pub organisation: Option<Organisation>,
}

#[derive(Clone, Debug, Eq, PartialEq, From)]
#[from(Interaction)]
pub struct UpdateInteractionRequest {
    pub id: InteractionId,
    pub host: Option<Url>, // base URL like: `https://core.dev.one-trust-solution.com`
    pub data: Option<Vec<u8>>, // empty for credential offer, json-serialized `Vec<ProofClaimSchema>` for proof request
    pub organisation: Option<Organisation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct InteractionRelations {
    pub organisation: Option<OrganisationRelations>,
}
