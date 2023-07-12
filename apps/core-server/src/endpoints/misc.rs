use axum::response::IntoResponse;
use axum::{http::StatusCode, Json};

use serde_json::{json, Value};

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

pub(crate) async fn health_check() -> impl IntoResponse {
    StatusCode::NO_CONTENT
}
