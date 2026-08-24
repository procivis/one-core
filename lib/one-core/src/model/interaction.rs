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
    /// the ecosystem this interaction runs under, once committed: either the one the user picked,
    /// or what autodetection settled on in the last step that could narrow it down
    pub ecosystem: Option<EcosystemId>,
    /// ecosystem state carried across the steps of the interaction: how far autodetection got,
    /// plus the data the ecosystem providers manage themselves
    pub ecosystem_data: InteractionEcosystems,
}

/// Ecosystem state carried across the steps of an interaction.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InteractionEcosystems {
    /// Information about the state of autodetection
    #[serde(default, skip_serializing_if = "EcosystemDetection::is_pending")]
    detection: EcosystemDetection,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    data: HashMap<EcosystemId, serde_json::Value>,
}

/// How far ecosystem autodetection has got on an interaction.
///
/// Autodetection only: an interaction whose [`Interaction::ecosystem`] is set runs under that
/// commitment and never consults this.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EcosystemDetection {
    /// autodetection has not run yet
    #[default]
    Pending,
    /// ecosystems still applicable; empty once none are left, and nothing will be assigned
    Applicable(Vec<EcosystemId>),
}

impl EcosystemDetection {
    /// Ecosystems still applicable, empty unless detection ran and found any.
    pub fn applicable(&self) -> &[EcosystemId] {
        match self {
            Self::Applicable(candidates) => candidates,
            Self::Pending => &[],
        }
    }

    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }
}

impl InteractionEcosystems {
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

    /// Serialize back into the representation stored on the interaction, `None` if neither
    /// detection nor any ecosystem has stored anything.
    pub fn into_stored(self) -> Result<Option<Vec<u8>>, serde_json::Error> {
        if self.detection.is_pending() && self.data.is_empty() {
            return Ok(None);
        }

        serde_json::to_vec(&self).map(Some)
    }

    pub fn detection(&self) -> &EcosystemDetection {
        &self.detection
    }

    pub fn set_detection(&mut self, detection: EcosystemDetection) {
        self.detection = detection;
    }

    /// Read the slot of `ecosystem`, `None` if the ecosystem has not stored anything yet.
    pub fn get<T: DeserializeOwned>(
        &self,
        ecosystem: &EcosystemId,
    ) -> Result<Option<T>, serde_json::Error> {
        let Some(value) = self.data.get(ecosystem) else {
            return Ok(None);
        };
        Ok(Some(serde_json::from_value(value.to_owned())?))
    }

    /// Replace the slot of `ecosystem`.
    pub fn set<T: Serialize>(
        &mut self,
        ecosystem: EcosystemId,
        data: &T,
    ) -> Result<(), serde_json::Error> {
        self.data.insert(ecosystem, serde_json::to_value(data)?);
        Ok(())
    }
}

// no `Eq`: `serde_json::Value` in `InteractionEcosystems` is only `PartialEq`
#[derive(Clone, Debug, PartialEq, Default)]
pub struct UpdateInteractionRequest {
    pub data: Option<Option<Vec<u8>>>,
    pub ecosystem: Option<Option<EcosystemId>>,
    pub ecosystem_data: Option<InteractionEcosystems>,
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
        let mut map = InteractionEcosystems::default();
        map.set(EcosystemId::from("EUDI"), &slot("eudi")).unwrap();
        map.set(EcosystemId::from("OTHER"), &slot("other")).unwrap();

        let stored = map.into_stored().unwrap();
        let map = InteractionEcosystems::from_stored(stored);

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
        let mut map = InteractionEcosystems::default();
        map.set(EcosystemId::from("EUDI"), &slot("eudi")).unwrap();

        assert!(
            map.get::<Slot>(&EcosystemId::from("OTHER"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_untouched_ecosystems_are_not_stored() {
        assert_eq!(
            None,
            InteractionEcosystems::default().into_stored().unwrap()
        );
    }

    #[test]
    fn test_detection_survives_a_round_trip_without_any_ecosystem_data() {
        let mut ecosystem_data = InteractionEcosystems::default();
        ecosystem_data.set_detection(EcosystemDetection::Applicable(vec![EcosystemId::from(
            "EUDI",
        )]));

        let stored = ecosystem_data.into_stored().unwrap();
        let ecosystem_data = InteractionEcosystems::from_stored(stored);

        assert_eq!(
            &EcosystemDetection::Applicable(vec![EcosystemId::from("EUDI")]),
            ecosystem_data.detection()
        );
    }

    #[test]
    fn test_narrowing_to_nothing_is_distinct_from_pending() {
        let mut ecosystem_data = InteractionEcosystems::default();
        ecosystem_data.set_detection(EcosystemDetection::Applicable(vec![]));

        let stored = ecosystem_data.into_stored().unwrap();
        let ecosystem_data = InteractionEcosystems::from_stored(stored);

        // narrowing down to nothing is a verdict, and must not read back as "not run yet"
        assert_eq!(
            &EcosystemDetection::Applicable(vec![]),
            ecosystem_data.detection()
        );
        assert!(!ecosystem_data.detection().is_pending());
        assert!(ecosystem_data.detection().applicable().is_empty());
    }

    #[test]
    fn test_absent_or_legacy_payload_reads_as_pending_and_empty() {
        assert_eq!(
            InteractionEcosystems::default(),
            InteractionEcosystems::from_stored(None)
        );

        // pre-map payload: a bare object that is not the ecosystem state
        let legacy = serde_json::to_vec(&slot("legacy")).unwrap();
        let ecosystem_data = InteractionEcosystems::from_stored(Some(legacy));
        assert!(ecosystem_data.detection().is_pending());
        assert!(
            ecosystem_data
                .get::<Slot>(&EcosystemId::from("EUDI"))
                .unwrap()
                .is_none()
        );
    }
}
