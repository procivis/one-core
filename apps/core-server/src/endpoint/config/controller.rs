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
    tag = "other",
    security(
        ("bearer" = [])
    ),
    summary = "Retrieve configuration",
    description = indoc::formatdoc! {"
    Returns the read-only system configuration, which exposes available
    components and their instance identifiers for your deployment.

    Call this during integration setup to confirm which components are
    enabled before referencing them in subsequent calls.

    See [Reading the Configuration](https://docs.procivis.ch/api/configuration)
    for general help and the
    [Core Configuration Reference](/reference/configuration/core) for
    complete details.
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
