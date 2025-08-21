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

    While the system configuration cannot be modified via the API, it
    is partially exposed through the API. Understanding the configuration
    is important for determining which solution components are available,
    how to invoke each component, and how to retrieve capabilities and
    instance reports.

    The API uses a pattern of referencing configuration instances rather
    than specifying types directly. Always check your system configuration
    to determine the correct reference identifiers for:

    - Credential formats
    - Key algorithms
    - Key storage providers
    - Issuance protocols
    - Verification protocols
    - Revocation methods
    - Datatypes
    - Transport protocols
    - Trust management solutions
    - DID methods

    Related guide: [Configuration](/configure)
"},
)]
pub(crate) async fn get_config(state: State<AppState>) -> OkOrErrorResponse<ConfigRestDTO> {
    let result: Result<ConfigRestDTO, _> = state
        .core
        .config_service
        .get_config()
        .map(ConfigRestDTO::from)
        .map(|mut config| {
            config.frontend.insert(
                "walletProviderEnabled".to_string(),
                serde_json::json!(state.config.enable_wallet_provider),
            );
            config
        });

    OkOrErrorResponse::from_result(result, state, "getting config")
}
