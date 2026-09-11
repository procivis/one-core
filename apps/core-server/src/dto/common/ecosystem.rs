use indexmap::IndexMap;
use one_core::model::ecosystem::{EcosystemOutcomes, EcosystemTrustResult};
use one_dto_mapper::From;
use proc_macros::options_not_nullable;
use serde::Serialize;
use utoipa::ToSchema;

/// One entry per ecosystem provider consulted, keyed by provider id.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(transparent)]
#[schema(example = json!({
    "EUDI": { "result": "NOT_TRUSTED", "error": { "code": "BR_0486", "message": "..." } }
}))]
pub(crate) struct EcosystemOutcomesRestDTO(IndexMap<String, EcosystemOutcomeRestDTO>);

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EcosystemOutcomeRestDTO {
    pub result: EcosystemTrustResultRestEnum,
    /// Why the provider did not trust the interaction. Absent when it did.
    pub error: Option<EcosystemErrorRestDTO>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(EcosystemTrustResult)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum EcosystemTrustResultRestEnum {
    Trusted,
    NotTrusted,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EcosystemErrorRestDTO {
    pub code: &'static str,
    pub message: String,
}

impl From<EcosystemOutcomes> for EcosystemOutcomesRestDTO {
    fn from(value: EcosystemOutcomes) -> Self {
        Self(
            value
                .iter()
                .map(|(ecosystem, outcome)| {
                    (
                        ecosystem.to_string(),
                        EcosystemOutcomeRestDTO {
                            result: outcome.result.into(),
                            error: outcome.error.to_owned().map(|error| EcosystemErrorRestDTO {
                                code: error.error_code.into(),
                                message: error.message,
                            }),
                        },
                    )
                })
                .collect(),
        )
    }
}
