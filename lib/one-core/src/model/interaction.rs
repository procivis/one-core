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
    pub data: Option<Vec<u8>>,
    pub organisation: Option<Organisation>,
    pub nonce_id: Option<Uuid>,
    pub interaction_type: InteractionType,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct UpdateInteractionRequest {
    pub host: Option<Option<Url>>, // base URL like: `https://core.dev.one-trust-solution.com`
    pub data: Option<Option<Vec<u8>>>,
    pub nonce_id: Option<Option<Uuid>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct InteractionRelations {
    pub organisation: Option<OrganisationRelations>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InteractionType {
    Issuance,
    Verification,
}

impl From<Interaction> for UpdateInteractionRequest {
    fn from(value: Interaction) -> Self {
        Self {
            host: Some(value.host),
            data: Some(value.data),
            nonce_id: Some(value.nonce_id),
        }
    }
}
