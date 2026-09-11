use std::collections::HashMap;

use proc_macros::Model;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use shared_types::{EcosystemId, InteractionId};
use strum::{AsRefStr, EnumString};
use time::OffsetDateTime;

use crate::model::ecosystem::EcosystemOutcomes;
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
    pub interaction_type: InteractionType,
    pub expires_at: Option<OffsetDateTime>,
    /// the ecosystem this interaction runs under, once committed: either the one the user picked,
    /// or what autodetection settled on in the last step that could narrow it down
    pub ecosystem: Option<EcosystemId>,
    /// ecosystem state carried across the steps of the interaction: the outcome of every step,
    /// plus the data the ecosystem providers manage themselves
    pub ecosystem_data: InteractionEcosystems,
}

/// Ecosystem state carried across the steps of an interaction.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InteractionEcosystems {
    /// Trust is resolved early but only reported when the interaction ends, so it is kept here
    /// in between. The ecosystems still trusted here are the ones autodetection still allows.
    #[serde(default, skip_serializing_if = "EcosystemOutcomes::is_empty")]
    outcomes: EcosystemOutcomes,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    data: HashMap<EcosystemId, serde_json::Value>,
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

    /// Serialize back into the representation stored on the interaction, `None` if no step and
    /// no ecosystem has stored anything.
    pub fn into_stored(self) -> Result<Option<Vec<u8>>, serde_json::Error> {
        if self.outcomes.is_empty() && self.data.is_empty() {
            return Ok(None);
        }

        serde_json::to_vec(&self).map(Some)
    }

    pub fn outcomes(&self) -> &EcosystemOutcomes {
        &self.outcomes
    }

    /// Returns false when nothing changed, so the caller can skip the write.
    pub fn merge_outcomes(&mut self, outcomes: &EcosystemOutcomes) -> bool {
        let before = self.outcomes.to_owned();
        self.outcomes.merge(outcomes);
        self.outcomes != before
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
    use crate::error::ErrorCode;
    use crate::model::history::HistoryErrorMetadata;

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
    fn test_narrowing_to_nothing_is_distinct_from_no_step_having_run() {
        let mut ecosystem_data = InteractionEcosystems::default();
        let mut only_candidate = EcosystemOutcomes::default();
        only_candidate.record(
            EcosystemId::from("EUDI"),
            Err(HistoryErrorMetadata {
                error_code: ErrorCode::BR_0477,
                message: "rejected".to_string(),
            }),
        );
        ecosystem_data.merge_outcomes(&only_candidate);

        let stored = ecosystem_data.into_stored().unwrap();
        let ecosystem_data = InteractionEcosystems::from_stored(stored);

        // no ecosystem left is a result, not the same as no step having run
        assert!(ecosystem_data.outcomes().applicable().is_empty());
        assert!(!ecosystem_data.outcomes().is_empty());
    }

    #[test]
    fn test_outcomes_survive_a_round_trip_and_fold_across_steps() {
        let mut ecosystem_data = InteractionEcosystems::default();
        let mut first = EcosystemOutcomes::default();
        first.record(EcosystemId::from("EUDI"), Ok(()));
        first.record(EcosystemId::from("OTHER"), Ok(()));

        assert!(ecosystem_data.merge_outcomes(&first));
        // the same step folded in again changes nothing, so nothing is written back
        assert!(!ecosystem_data.merge_outcomes(&first));

        let stored = ecosystem_data.into_stored().unwrap();
        let mut ecosystem_data = InteractionEcosystems::from_stored(stored);
        assert_eq!(&first, ecosystem_data.outcomes());

        // a later step rejects one of them, and that wins over the earlier pass
        let mut second = EcosystemOutcomes::default();
        second.record(
            EcosystemId::from("EUDI"),
            Err(HistoryErrorMetadata {
                error_code: ErrorCode::BR_0477,
                message: "rejected".to_string(),
            }),
        );
        assert!(ecosystem_data.merge_outcomes(&second));

        assert_eq!(
            vec![EcosystemId::from("OTHER")],
            ecosystem_data.outcomes().applicable()
        );
    }

    #[test]
    fn test_absent_or_legacy_payload_reads_as_empty() {
        assert_eq!(
            InteractionEcosystems::default(),
            InteractionEcosystems::from_stored(None)
        );

        // pre-map payload: a bare object that is not the ecosystem state
        let legacy = serde_json::to_vec(&slot("legacy")).unwrap();
        let ecosystem_data = InteractionEcosystems::from_stored(Some(legacy));
        assert!(ecosystem_data.outcomes().is_empty());
        assert!(
            ecosystem_data
                .get::<Slot>(&EcosystemId::from("EUDI"))
                .unwrap()
                .is_none()
        );
    }
}
