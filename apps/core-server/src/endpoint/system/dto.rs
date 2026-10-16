use serde::Serialize;
use utoipa::ToSchema;

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReadinessResponseRestDTO {
    pub status: HealthStatusRestEnum,
    pub checks: ReadinessChecksRestDTO,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReadinessChecksRestDTO {
    pub database: HealthStatusRestEnum,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub(crate) enum HealthStatusRestEnum {
    Healthy,
    Unhealthy,
}
