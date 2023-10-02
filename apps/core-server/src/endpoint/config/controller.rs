use super::dto::ConfigRestDTO;
use crate::router::AppState;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

#[utoipa::path(
    get,
    path = "/api/config/v1",
    responses(
        (status = 200, description = "OK", body = ConfigRestDTO),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal error")
    ),
    tag = "other",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_config(state: State<AppState>) -> Response {
    let result = state.core.config_service.get_config();
    match result {
        Ok(config) => (StatusCode::OK, Json(ConfigRestDTO::from(config))).into_response(),
        Err(error) => {
            tracing::error!("Failed to get config: {:?}", error);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
