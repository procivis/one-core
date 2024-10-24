use axum::extract::State;

use super::dto::ConfigRestDTO;
use crate::dto::response::OkOrErrorResponse;
use crate::router::AppState;

#[utoipa::path(
    get,
    path = "/api/config/v1",
    responses(OkOrErrorResponse<ConfigRestDTO>),
    tag = "other",
    security(
        ("bearer" = [])
    ),
    summary = "Retrieve configuration",
    description = "Returns the system configuration. See the [configuration](/api/configuration) guide for more information.",
)]
pub(crate) async fn get_config(state: State<AppState>) -> OkOrErrorResponse<ConfigRestDTO> {
    let result = state.core.config_service.get_config();
    OkOrErrorResponse::from_result(result, state, "getting config")
}
