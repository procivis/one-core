use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use one_core::{
    data_model::ConnectRequest,
    error::{OneCoreError, SSIError},
};

use crate::{
    data_model::{ConnectRequestDTO, ConnectResponseDTO, PostSsiConnect},
    AppState,
};

#[utoipa::path(
    post,
    path = "/ssi/temporary-issuer/v1/connect",
    request_body = ConnectRequestDTO,
    responses(
        (status = 200, description = "OK", body = ConnectResponseDTO),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Server error"),
    ),
    params(
        PostSsiConnect
    ),
    tag = "ssi",
)]
pub(crate) async fn ssi_issuer_connect(
    state: State<AppState>,
    Query(query): Query<PostSsiConnect>,
    Json(request): Json<ConnectRequestDTO>,
) -> Response {
    let request = ConnectRequest {
        credential: query.credential,
        did: request.did,
    };

    let result = state.core.issuer_connect(&query.protocol, &request).await;

    match result {
        Ok(result) => (StatusCode::OK, Json(ConnectResponseDTO::from(result))).into_response(),
        Err(OneCoreError::SSIError(SSIError::IncorrectCredentialState)) => {
            tracing::error!("Already issued");
            (StatusCode::CONFLICT, "Already issued").into_response()
        }
        Err(OneCoreError::SSIError(SSIError::MissingCredential)) => {
            tracing::error!("Missing credential");
            (StatusCode::NOT_FOUND, "Missing credential").into_response()
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
