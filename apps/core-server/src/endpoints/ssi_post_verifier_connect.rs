use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use one_core::{
    data_model::ConnectVerifierRequest,
    error::{OneCoreError, SSIError},
};

use crate::{
    data_model::{ConnectRequestDTO, ConnectVerifierResponseDTO, PostSsiVerifierConnectQuery},
    AppState,
};

#[utoipa::path(
    post,
    path = "/ssi/temporary-verifier/v1/connect",
    request_body = ConnectRequestDTO,
    responses(
        (status = 200, description = "OK", body = ConnectVerifierResponseDTO),
        (status = 400, description = "Invalid request"),
        (status = 404, description = "Proof not found"),
        (status = 409, description = "Invalid proof state"),
        (status = 500, description = "Server error"),
    ),
    params(
        PostSsiVerifierConnectQuery
    ),
    tag = "ssi",
)]
pub(crate) async fn ssi_verifier_connect(
    state: State<AppState>,
    Query(query): Query<PostSsiVerifierConnectQuery>,
    Json(request): Json<ConnectRequestDTO>,
) -> Response {
    let request = ConnectVerifierRequest {
        proof: query.proof,
        did: request.did,
    };

    let result = state.core.verifier_connect(&query.protocol, &request).await;

    match result {
        Ok(result) => (
            StatusCode::OK,
            Json(ConnectVerifierResponseDTO::from(result)),
        )
            .into_response(),
        Err(OneCoreError::SSIError(SSIError::IncorrectProofState)) => {
            tracing::warn!("Already finished");
            (StatusCode::CONFLICT, "Already finished").into_response()
        }
        Err(OneCoreError::SSIError(SSIError::MissingCredential)) => {
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
