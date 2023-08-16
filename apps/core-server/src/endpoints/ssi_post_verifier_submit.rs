use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use one_core::{
    data_model::VerifierSubmitRequest,
    error::{OneCoreError, SSIError},
};

use crate::{data_model::ProofRequestQueryParams, AppState};

#[utoipa::path(
    post,
    path = "/ssi/temporary-verifier/v1/submit",
    request_body = String, // signed JWT
    responses(
        (status = 204, description = "OK"),
        (status = 400, description = "Invalid request"),
        (status = 404, description = "Proof not found"),
        (status = 409, description = "Invalid proof state"),
        (status = 500, description = "Server error"),
    ),
    params(
        ("proof" = Uuid, Query, description = "Proof request id")
    ),
    tag = "ssi",
)]
pub(crate) async fn ssi_verifier_submit(
    state: State<AppState>,
    Query(query): Query<ProofRequestQueryParams>,
    request: String,
) -> Response {
    let request = VerifierSubmitRequest {
        proof: query.proof,
        proof_submit_request: request,
    };

    let result = state.core.verifier_submit(&request).await;

    match result {
        Ok(_) => (StatusCode::NO_CONTENT).into_response(),
        Err(OneCoreError::SSIError(SSIError::IncorrectProofState)) => {
            tracing::warn!("Already finished");
            (StatusCode::CONFLICT, "Already finished").into_response()
        }
        Err(OneCoreError::SSIError(SSIError::MissingProof)) => {
            tracing::error!("Missing proof");
            (StatusCode::NOT_FOUND, "Missing proof").into_response()
        }
        Err(OneCoreError::SSIError(SSIError::UnsupportedTransportProtocol)) => {
            tracing::error!("Unsupported transport protocol");
            (StatusCode::BAD_REQUEST, "Unsupported transport protocol").into_response()
        }
        Err(e) => {
            tracing::error!("Error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
