use axum::extract::State;
use one_core::service::config::dto::ConfigDTO;
use one_core::service::error::ServiceError;
use one_dto_mapper::convert_inner;

use super::dto::ConfigRestDTO;
use crate::dto::response::OkOrErrorResponse;
use crate::router::AppState;

#[proc_macros::endpoint(
    permissions = [],
    get,
    path = "/api/config/v1",
    responses(OkOrErrorResponse<ConfigRestDTO>),
    tag = "other",
    security(
        ("bearer" = [])
    ),
    summary = "Retrieve configuration",
    description = indoc::formatdoc! {"
    Returns the system configuration.

    The configuration is read-only via the API but exposes the available
    components and their instance identifiers. Use this to determine which
    credential formats, key algorithms, DID methods, protocols, and other
    components are available in your deployment, and how to reference them
    in other API calls.

    Related guide: [Configuration in the API](https://docs.procivis.ch/api/configuration)
"},
)]
pub(crate) async fn get_config(state: State<AppState>) -> OkOrErrorResponse<ConfigRestDTO> {
    let result = state.core.config_service.get_config();
    OkOrErrorResponse::from_result(
        convert_inner::<Result<ConfigDTO, ServiceError>, ConfigRestDTO>(result),
        state,
        "getting config",
    )
}
