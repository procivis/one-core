use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use proc_macros::endpoint;
use serde_json::{Value, json};

use super::dto::{HealthStatusRestEnum, ReadinessChecksRestDTO, ReadinessResponseRestDTO};
use crate::build_info;
use crate::metrics::encode_metrics;
use crate::router::AppState;

const DATABASE_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

#[endpoint(
    permissions = [],
    get,
    path = "/system/build-info",
    responses(
        (status = 200, description = "Ok")
    ),
    security(
        ("bearer" = [])
    ),
    tag = "other",
    summary = "Retrieve version",
    description = indoc::formatdoc! {"
    Returns build and version information for Core service. Useful
    for troubleshooting and when reporting issues to support.
    "},
)]
pub(crate) async fn get_build_info() -> Json<Value> {
    Json::from(json!({
        "target": String::from(build_info::BUILD_RUST_CHANNEL),
        "build_time": String::from(build_info::BUILD_TIME),
        "branch": String::from(build_info::BRANCH),
        "tag": String::from(build_info::TAG),
        "commit": String::from(build_info::COMMIT_HASH),
        "rust_version": String::from(build_info::RUST_VERSION),
        "pipeline_id": String::from(build_info::CI_PIPELINE_ID),
    }))
}

#[endpoint(
    permissions = [],
    get,
    path = "/system/health/liveness",
    responses(
        (status = 200, description = "OK")
    ),
    tag = "other",
    summary = "Liveness probe",
    description = "Returns `200` while the server is running. Dependencies are not checked.",
)]
pub(crate) async fn liveness() -> StatusCode {
    StatusCode::OK
}

#[endpoint(
    permissions = [],
    get,
    path = "/system/health/readiness",
    responses(
        (status = 200, description = "All checks healthy", body = ReadinessResponseRestDTO),
        (status = 503, description = "A check is unhealthy", body = ReadinessResponseRestDTO)
    ),
    tag = "other",
    summary = "Readiness probe",
    description = "Checks the dependencies the server needs to serve requests. Returns `503` when any check fails.",
)]
pub(crate) async fn readiness(
    state: State<AppState>,
) -> (StatusCode, Json<ReadinessResponseRestDTO>) {
    let database = match tokio::time::timeout(DATABASE_CHECK_TIMEOUT, state.db.ping()).await {
        Ok(Ok(())) => HealthStatusRestEnum::Healthy,
        Ok(Err(error)) => {
            tracing::warn!(%error, "Database readiness check failed");
            HealthStatusRestEnum::Unhealthy
        }
        Err(_) => {
            tracing::warn!("Database readiness check timed out");
            HealthStatusRestEnum::Unhealthy
        }
    };

    let status_code = match database {
        HealthStatusRestEnum::Healthy => StatusCode::OK,
        HealthStatusRestEnum::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
    };
    (
        status_code,
        Json(ReadinessResponseRestDTO {
            status: database,
            checks: ReadinessChecksRestDTO { database },
        }),
    )
}

#[endpoint(
    permissions = [],
    get,
    path = "/system/metrics",
    responses(
        (status = 200, description = "OK"),
        (status = 500, description = "Internal error")
    ),
    tag = "other",
    summary = "Retrieve metrics",
    description = "Returns system metrics.",
)]
pub(crate) async fn get_metrics() -> Response {
    match encode_metrics() {
        Ok(result) => (StatusCode::OK, result).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Metrics encoding error: {error:?}"),
        )
            .into_response(),
    }
}
