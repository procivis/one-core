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
    description = indoc::formatdoc! {"
    Returns the system configuration.

    While the system configuration is not modifiable via the API, it
    is partially exposed to the API and is important for understanding
    which parts of the solution are available, how to invoke each
    component and for retrieving capabilities, reports that reflect
    properties of instances.

    The pattern of referencing configuration instances, rather than
    specifying types directly, is used throughout the API. Always refer
    to your system configuration to determine correct reference
    identifiers for:

    - Credential formats
    - Key algorithms
    - Key storage providers
    - Exchange protocols
    - Revocation methods
    - Datatypes
    - Transport protocols
    - Trust management solutions
    - DID methods

    Related guide: [Configuration](/configure)
"},
)]
pub(crate) async fn get_config(state: State<AppState>) -> OkOrErrorResponse<ConfigRestDTO> {
    let result = state.core.config_service.get_config();
    OkOrErrorResponse::from_result(result, state, "getting config")
}
