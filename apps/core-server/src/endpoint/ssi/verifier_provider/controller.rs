use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum_extra::extract::WithRejection;
use one_core::error::{ErrorCode, ErrorCodeMixin};
use proc_macros::endpoint;
use reqwest::StatusCode;

use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{ErrorResponse, OkOrErrorResponse};
use crate::endpoint::ssi::verifier_provider::dto::VerifierProviderResponseRestDTO;
use crate::router::AppState;

#[endpoint(
    permissions = [],
    get,
    path = "/ssi/verifier-provider/v1/{verifierProvider}",
    responses((status = OK, description = "OK", body = VerifierProviderResponseRestDTO), ErrorResponse),
    params(
        ("verifierProvider" = String, Path, description = "Verifier Provider ID")
    ),
    tag = "ssi",
    summary = "Retrieve Verifier Provider info",
    description = indoc::formatdoc! {"
    Returns configuration and policies from the Verifier Provider.
"},
)]
pub(crate) async fn get_verification_provider(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<String>, ErrorResponseRestDTO>,
) -> Response {
    let result = state
        .core
        .verifier_provider_service
        .get_verifier_by_id(id.as_str())
        .await;

    match result {
        Err(error) if matches!(error.error_code(), ErrorCode::BR_0430) => {
            tracing::error!("Verifier provider not found: {error}");
            StatusCode::NOT_FOUND.into_response()
        }
        result => OkOrErrorResponse::<VerifierProviderResponseRestDTO>::from_result(
            result,
            state,
            "retrieving verifier provider",
        )
        .into_response(),
    }
}
