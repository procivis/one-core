use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use shared_types::EcosystemId;

use crate::error::ErrorCodeMixin;
use crate::model::history::HistoryErrorMetadata;

/// Whether an artifact satisfies the ecosystem rules, and whether trust was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EcosystemTrustResult {
    Trusted,
    /// The ecosystem rules are satisfied, but no issuer trust check applies.
    Compliant,
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

    pub fn is_accepted(&self) -> bool {
        self.result != EcosystemTrustResult::NotTrusted
    }
}

impl From<EcosystemTrustResult> for EcosystemOutcome {
    fn from(result: EcosystemTrustResult) -> Self {
        Self {
            result,
            error: None,
        }
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

    pub fn record(&mut self, ecosystem: EcosystemId, outcome: impl Into<EcosystemOutcome>) {
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

    /// The ecosystems whose rules the artifact satisfies, with or without established trust.
    pub fn applicable(&self) -> Vec<EcosystemId> {
        self.0
            .iter()
            .filter(|(_, outcome)| outcome.is_accepted())
            .map(|(ecosystem, _)| ecosystem.to_owned())
            .collect()
    }

    /// Rejections keep the first reason. Otherwise, any trusted input establishes trust;
    /// inputs that are all compliant leave the ecosystem compliant.
    pub fn merge(&mut self, other: &Self) {
        for (ecosystem, outcome) in other.iter() {
            if self.get(ecosystem).is_some_and(|kept| {
                !kept.is_accepted() || (kept.is_trusted() && outcome.is_accepted())
            }) {
                continue;
            }
            self.0.insert(ecosystem.to_owned(), outcome.to_owned());
        }
    }

    /// Merge every credential's outcome. All must be accepted, and at least one trusted,
    /// for an ecosystem to be trusted.
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
    use rstest::rstest;
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

    #[rstest]
    #[case(
        EcosystemTrustResult::Compliant,
        EcosystemTrustResult::Compliant,
        EcosystemTrustResult::Compliant
    )]
    #[case(
        EcosystemTrustResult::Compliant,
        EcosystemTrustResult::Trusted,
        EcosystemTrustResult::Trusted
    )]
    #[case(
        EcosystemTrustResult::Trusted,
        EcosystemTrustResult::Compliant,
        EcosystemTrustResult::Trusted
    )]
    #[case(
        EcosystemTrustResult::Compliant,
        EcosystemTrustResult::NotTrusted,
        EcosystemTrustResult::NotTrusted
    )]
    #[case(
        EcosystemTrustResult::NotTrusted,
        EcosystemTrustResult::Compliant,
        EcosystemTrustResult::NotTrusted
    )]
    fn test_merge_compliant_inputs(
        #[case] first: EcosystemTrustResult,
        #[case] second: EcosystemTrustResult,
        #[case] expected: EcosystemTrustResult,
    ) {
        let ecosystem = EcosystemId::from("EUDI");
        let inputs = [first, second].map(|result| {
            let mut outcomes = EcosystemOutcomes::default();
            if result == EcosystemTrustResult::NotTrusted {
                outcomes.record(ecosystem.clone(), Err(error("rejected")));
            } else {
                outcomes.record(ecosystem.clone(), result);
            }
            outcomes
        });
        let merged = EcosystemOutcomes::merged(&inputs);
        let outcome = merged.get(&ecosystem).unwrap();
        assert_eq!(expected, outcome.result);
        assert_eq!(
            expected != EcosystemTrustResult::NotTrusted,
            merged.applicable().contains(&ecosystem)
        );
        assert_eq!(
            expected == EcosystemTrustResult::NotTrusted,
            outcome.error.is_some()
        );
    }

    #[test]
    fn test_serialized_shape_is_the_ecosystem_map() {
        let mut stored = outcomes(&[("EUDI", Ok(())), ("OTHER", Err(error("why")))]);
        stored.record(
            "COMPLIANT_ECOSYSTEM".into(),
            EcosystemTrustResult::Compliant,
        );
        let serialized = serde_json::to_value(&stored).unwrap();

        assert_eq!(
            serde_json::json!({
                "EUDI": { "result": "TRUSTED" },
                "COMPLIANT_ECOSYSTEM": { "result": "COMPLIANT" },
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
        let mut stored = outcomes(&[("EUDI", Ok(())), ("OTHER", Err(error("why")))]);
        stored.record(
            "COMPLIANT_ECOSYSTEM".into(),
            EcosystemTrustResult::Compliant,
        );
        let raw = serde_json::to_vec(&stored).unwrap();

        assert_eq!(stored, serde_json::from_slice(&raw).unwrap());
    }
}
