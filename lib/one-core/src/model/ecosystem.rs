use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use shared_types::EcosystemId;

use crate::error::ErrorCodeMixin;
use crate::model::history::HistoryErrorMetadata;

/// Not [`crate::model::history::TrustResolutionResult`]. An ecosystem either validated the
/// artifact or it did not. There is no third, unknown state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EcosystemTrustResult {
    Trusted,
    NotTrusted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EcosystemOutcome {
    pub result: EcosystemTrustResult,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<HistoryErrorMetadata>,
}

impl EcosystemOutcome {
    pub fn is_trusted(&self) -> bool {
        self.result == EcosystemTrustResult::Trusted
    }
}

impl From<Result<(), HistoryErrorMetadata>> for EcosystemOutcome {
    fn from(value: Result<(), HistoryErrorMetadata>) -> Self {
        match value {
            Ok(()) => Self {
                result: EcosystemTrustResult::Trusted,
                error: None,
            },
            Err(error) => Self {
                result: EcosystemTrustResult::NotTrusted,
                error: Some(error),
            },
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EcosystemOutcomes(IndexMap<EcosystemId, EcosystemOutcome>);

impl EcosystemOutcomes {
    pub fn validated(ecosystem: EcosystemId) -> Self {
        let mut outcomes = Self::default();
        outcomes.record(ecosystem, Ok(()));
        outcomes
    }

    pub fn rejected(ecosystem: EcosystemId, error: &impl ErrorCodeMixin) -> Self {
        let mut outcomes = Self::default();
        outcomes.record(
            ecosystem,
            Err(HistoryErrorMetadata {
                error_code: error.error_code(),
                message: error.to_string(),
            }),
        );
        outcomes
    }

    pub fn record(&mut self, ecosystem: EcosystemId, outcome: Result<(), HistoryErrorMetadata>) {
        self.0.insert(ecosystem, outcome.into());
    }

    pub fn get(&self, ecosystem: &EcosystemId) -> Option<&EcosystemOutcome> {
        self.0.get(ecosystem)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&EcosystemId, &EcosystemOutcome)> {
        self.0.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The ecosystems that validated the artifact.
    pub fn applicable(&self) -> Vec<EcosystemId> {
        self.0
            .iter()
            .filter(|(_, outcome)| outcome.is_trusted())
            .map(|(ecosystem, _)| ecosystem.to_owned())
            .collect()
    }

    /// Once an ecosystem is rejected it stays rejected, and keeps the first reason.
    pub fn merge(&mut self, other: &Self) {
        for (ecosystem, outcome) in other.iter() {
            if self.get(ecosystem).is_some_and(|kept| !kept.is_trusted()) {
                continue;
            }
            self.0.insert(ecosystem.to_owned(), outcome.to_owned());
        }
    }

    /// Merge the outcomes of every credential in a submission. An ecosystem is trusted only if
    /// it validated all of them.
    pub fn merged<'a>(per_credential: impl IntoIterator<Item = &'a Self>) -> Self {
        let mut merged = Self::default();
        for outcomes in per_credential {
            merged.merge(outcomes);
        }
        merged
    }
}

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;

    use super::*;
    use crate::error::ErrorCode;

    fn error(message: &str) -> HistoryErrorMetadata {
        HistoryErrorMetadata {
            error_code: ErrorCode::BR_0477,
            message: message.to_string(),
        }
    }

    fn outcomes(entries: &[(&str, Result<(), HistoryErrorMetadata>)]) -> EcosystemOutcomes {
        let mut outcomes = EcosystemOutcomes::default();
        for (ecosystem, outcome) in entries {
            outcomes.record(EcosystemId::from(*ecosystem), outcome.to_owned());
        }
        outcomes
    }

    #[test]
    fn test_merge_keeps_the_first_rejection() {
        let mut merged = outcomes(&[("EUDI", Ok(())), ("OTHER", Ok(()))]);
        merged.merge(&outcomes(&[("EUDI", Err(error("first")))]));
        merged.merge(&outcomes(&[
            ("EUDI", Err(error("second"))),
            ("OTHER", Ok(())),
        ]));

        assert_eq!(
            outcomes(&[("EUDI", Err(error("first"))), ("OTHER", Ok(()))]),
            merged
        );
    }

    #[test]
    fn test_serialized_shape_is_the_ecosystem_map() {
        let serialized =
            serde_json::to_value(outcomes(&[("EUDI", Ok(())), ("OTHER", Err(error("why")))]))
                .unwrap();

        assert_eq!(
            serde_json::json!({
                "EUDI": { "result": "TRUSTED" },
                "OTHER": {
                    "result": "NOT_TRUSTED",
                    "error": { "error_code": "BR_0477", "message": "why" },
                },
            }),
            serialized
        );
    }

    #[test]
    fn test_round_trips_through_the_stored_representation() {
        let stored = outcomes(&[("EUDI", Ok(())), ("OTHER", Err(error("why")))]);
        let raw = serde_json::to_vec(&stored).unwrap();

        assert_eq!(stored, serde_json::from_slice(&raw).unwrap());
    }
}
