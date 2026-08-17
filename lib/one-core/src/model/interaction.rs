use proc_macros::Model;
use serde::{Deserialize, Serialize};
use shared_types::{EcosystemId, InteractionId, NonceId};
use strum::{AsRefStr, EnumString};
use time::OffsetDateTime;

use crate::model::organisation::Organisation;
use crate::model::relation::Related;

#[derive(Clone, Debug, Model)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct Interaction {
    #[model(id)]
    pub id: InteractionId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    /// additional data for the interaction, usually managed by the exchange protocol
    pub data: Option<Vec<u8>>,
    pub organisation: Related<Organisation>,
    pub nonce_id: Option<NonceId>,
    pub interaction_type: InteractionType,
    pub expires_at: Option<OffsetDateTime>,
    pub ecosystem: Option<EcosystemId>,
    /// additional data managed by the ecosystem provider
    pub ecosystem_data: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct UpdateInteractionRequest {
    pub data: Option<Option<Vec<u8>>>,
    pub ecosystem: Option<Option<EcosystemId>>,
    pub ecosystem_data: Option<Option<Vec<u8>>>,
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
            ecosystem: Some(value.ecosystem),
            ecosystem_data: Some(value.ecosystem_data),
        }
    }
}
