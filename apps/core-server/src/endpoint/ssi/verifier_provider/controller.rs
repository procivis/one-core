use axum::extract::{Path, State};
use axum_extra::extract::WithRejection;
use proc_macros::endpoint;

use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::OkOrErrorResponse;
use crate::endpoint::ssi::verifier_provider::dto::VerifierProviderResponseDTO;
use crate::router::AppState;

#[endpoint(
    permissions = [],
    get,
    path = "/ssi/verifier-provider/v1/{verifierProvider}",
    responses(OkOrErrorResponse<VerifierProviderResponseDTO>),
    params(
        ("verifierProvider" = String, Path, description = "Verifier provider ID")
    ),
    tag = "verifier-provider",
    security(
        ("bearer" = [])
    ),
    summary = "Retrieve verifier provider info",
    description = indoc::formatdoc! {"
    Retrieves information about a verifier provider.
"},
)]
pub(crate) async fn get_verification_provider(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<String>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<VerifierProviderResponseDTO> {
    let result = state
        .core
        .verifier_provider_service
        .get_verifier_by_id(id.as_str());
    OkOrErrorResponse::from_result(result, state, "retrieving verifier provider")
}
