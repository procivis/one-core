use std::future;

use axum::handler::Handler;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

use crate::build_info;
use crate::metrics::encode_metrics;

#[utoipa::path(
    get,
    path = "/build-info",
    responses(
        (status = 200, description = "Ok")
    ),
    tag = "other",
    summary = "Retrieve version",
    description = "Returns version information for Procivis One.",
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

#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 204, description = "No content")
    ),
    tag = "other",
    summary = "Health check",
    description = "Returns a `204` response when the system is healthy.",
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
    summary = "Retrieve metrics",
    description = "Returns system metrics.",
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

pub(crate) fn get_openapi_yaml<S>(openapi: &utoipa::openapi::OpenApi) -> impl Handler<((),), S> {
    let yaml = openapi.to_yaml().unwrap();
    move || future::ready((StatusCode::OK, yaml.clone()).into_response())
}
