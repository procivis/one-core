use serde::{Deserialize, Serialize};
use shared_types::NonceId;
use strum::{AsRefStr, EnumString};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::organisation::{Organisation, OrganisationRelations};

pub type InteractionId = Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Interaction {
    pub id: InteractionId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub data: Option<Vec<u8>>,
    pub organisation: Option<Organisation>,
    pub nonce_id: Option<NonceId>,
    pub interaction_type: InteractionType,
    pub expires_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct UpdateInteractionRequest {
    pub data: Option<Option<Vec<u8>>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct InteractionRelations {
    pub organisation: Option<OrganisationRelations>,
}

#[derive(Clone, Debug, Eq, PartialEq, EnumString, AsRefStr, Serialize, Deserialize)]
#[strum(serialize_all = "UPPERCASE")]
#[serde(rename_all = "UPPERCASE")]
pub enum InteractionType {
    Issuance,
    Verification,
}

impl From<Interaction> for UpdateInteractionRequest {
    fn from(value: Interaction) -> Self {
        Self {
            data: Some(value.data),
        }
    }
}
