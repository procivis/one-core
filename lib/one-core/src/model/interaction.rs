use std::collections::HashMap;

use proc_macros::Model;
use serde::de::DeserializeOwned;
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
    /// additional data managed by the ecosystem providers
    pub ecosystem_data: EcosystemDataMap,
}

/// Per-ecosystem slots of [`Interaction::ecosystem_data`].
///
/// Each ecosystem owns its own entry, so that several candidate ecosystems can carry state
/// through a multi-step interaction without clobbering each other.
// `PartialEq` unconditionally: `UpdateInteractionRequest` derives it outside of test builds too
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EcosystemDataMap(HashMap<EcosystemId, serde_json::Value>);

impl EcosystemDataMap {
    /// Parse the stored column value.
    pub fn from_stored(stored: Option<Vec<u8>>) -> Self {
        stored
            .and_then(|raw| {
                serde_json::from_slice(&raw)
                    .inspect_err(|e| tracing::warn!("failed to deserialize ecosystem data: {e}"))
                    .ok()
            })
            .unwrap_or_default()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Read the slot of `ecosystem`, `None` if the ecosystem has not stored anything yet.
    pub fn get<T: DeserializeOwned>(
        &self,
        ecosystem: &EcosystemId,
    ) -> Option<Result<T, serde_json::Error>> {
        let value = self.0.get(ecosystem)?;
        Some(serde_json::from_value(value.to_owned()))
    }

    /// Replace the slot of `ecosystem`.
    pub fn set<T: Serialize>(
        &mut self,
        ecosystem: EcosystemId,
        data: &T,
    ) -> Result<(), serde_json::Error> {
        self.0.insert(ecosystem, serde_json::to_value(data)?);
        Ok(())
    }

    /// Serialize back into the representation stored on the interaction, `None` if no
    /// ecosystem has stored anything.
    pub fn into_stored(self) -> Result<Option<Vec<u8>>, serde_json::Error> {
        if self.is_empty() {
            return Ok(None);
        }

        serde_json::to_vec(&self).map(Some)
    }
}

// no `Eq`: `serde_json::Value` in `EcosystemDataMap` is only `PartialEq`
#[derive(Clone, Debug, PartialEq, Default)]
pub struct UpdateInteractionRequest {
    pub data: Option<Option<Vec<u8>>>,
    pub ecosystem: Option<Option<EcosystemId>>,
    pub ecosystem_data: Option<EcosystemDataMap>,
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

#[cfg(test)]
mod tests {
    use similar_asserts::assert_eq;

    use super::*;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Slot {
        value: String,
    }

    fn slot(value: &str) -> Slot {
        Slot {
            value: value.to_string(),
        }
    }

    #[test]
    fn test_ecosystem_data_slots_are_kept_per_ecosystem() {
        let mut map = EcosystemDataMap::default();
        map.set(EcosystemId::from("EUDI"), &slot("eudi")).unwrap();
        map.set(EcosystemId::from("OTHER"), &slot("other")).unwrap();

        let stored = map.into_stored().unwrap();
        let map = EcosystemDataMap::from_stored(stored);

        assert_eq!(
            slot("eudi"),
            map.get::<Slot>(&EcosystemId::from("EUDI"))
                .unwrap()
                .unwrap()
        );
        assert_eq!(
            slot("other"),
            map.get::<Slot>(&EcosystemId::from("OTHER"))
                .unwrap()
                .unwrap()
        );
    }

    #[test]
    fn test_ecosystem_data_of_unknown_ecosystem_is_missing() {
        let mut map = EcosystemDataMap::default();
        map.set(EcosystemId::from("EUDI"), &slot("eudi")).unwrap();

        assert!(map.get::<Slot>(&EcosystemId::from("OTHER")).is_none());
    }

    #[test]
    fn test_empty_ecosystem_data_is_not_stored() {
        assert_eq!(None, EcosystemDataMap::default().into_stored().unwrap());
    }

    #[test]
    fn test_ecosystem_data_of_absent_or_legacy_payload_is_empty() {
        assert_eq!(
            EcosystemDataMap::default(),
            EcosystemDataMap::from_stored(None)
        );

        // pre-map payload: a bare object that is not a map of ecosystem slots
        let legacy = serde_json::to_vec(&slot("legacy")).unwrap();
        let map = EcosystemDataMap::from_stored(Some(legacy));
        assert!(map.get::<Slot>(&EcosystemId::from("EUDI")).is_none());
    }
}
