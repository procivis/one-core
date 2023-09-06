use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use one_core::service::error::ServiceError;

use crate::data_model::ProofRequestQueryParams;
use crate::AppState;

#[utoipa::path(
    post,
    path = "/ssi/temporary-verifier/v1/reject",
    responses(
        (status = 204, description = "No content"),
        (status = 400, description = "Wrong proof request state"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Not found"),
    ),
    params(
        ("proof" = Uuid, Query, description = "Proof request id")
    ),
    tag = "ssi",
)]
pub(crate) async fn ssi_post_verifier_reject_proof_request(
    state: State<AppState>,
    Query(query): Query<ProofRequestQueryParams>,
) -> Response {
    let result = state.core.proof_service.reject_proof(&query.proof).await;

    match result {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => match error {
            ServiceError::NotUpdated => StatusCode::BAD_REQUEST.into_response(),
            ServiceError::NotFound => StatusCode::NOT_FOUND.into_response(),
            _ => {
                tracing::error!("Error while rejecting proof");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        },
    }
}
