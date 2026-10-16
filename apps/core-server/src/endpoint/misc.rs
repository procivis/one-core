use std::future;

use axum::handler::Handler;
use axum::http::StatusCode;
use axum::response::IntoResponse;

#[expect(clippy::unwrap_used)]
pub(crate) fn get_openapi_yaml<S>(openapi: &utoipa::openapi::OpenApi) -> impl Handler<((),), S> {
    let yaml = openapi.to_yaml().unwrap();
    move || future::ready((StatusCode::OK, yaml.clone()).into_response())
}
