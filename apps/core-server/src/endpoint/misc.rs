use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

use crate::metrics::encode_metrics;

#[utoipa::path(
    get,
    path = "/build-info",
    responses(
        (status = 200, description = "Ok")
    ),
    tag = "other",
)]
pub(crate) async fn get_build_info() -> Json<Value> {
    use shadow_rs::shadow;

    shadow!(build);

    Json::from(json!({
        "target": String::from(build::BUILD_RUST_CHANNEL),
        "build_time": String::from(build::BUILD_TIME),
        "branch": String::from(build::BRANCH),
        "tag": String::from(build::TAG),
        "commit": String::from(build::COMMIT_HASH),
        "rust_version": String::from(build::RUST_VERSION),
        "pipeline_id": String::from(build::CI_PIPELINE_ID),
    }))
}

#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 204, description = "No content")
    ),
    tag = "other",
)]
pub(crate) async fn health_check() -> impl IntoResponse {
    StatusCode::NO_CONTENT
}

#[utoipa::path(
    get,
    path = "/metrics",
    responses(
        (status = 200, description = "OK"),
        (status = 500, description = "Internal error")
    ),
    tag = "other",
)]
pub(crate) async fn get_metrics() -> Response {
    match encode_metrics() {
        Ok(result) => (StatusCode::OK, result).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Metrics encoding error: {:?}", error),
        )
            .into_response(),
    }
}
