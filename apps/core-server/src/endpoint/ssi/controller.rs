use super::dto::{
    ConnectIssuerResponseRestDTO, ConnectRequestRestDTO, ConnectVerifierResponseRestDTO,
    HandleInvitationRequestRestDTO, HandleInvitationResponseRestDTO,
    PostSsiIssuerConnectQueryParams, PostSsiVerifierConnectQueryParams, ProofRequestQueryParams,
};
use crate::AppState;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use one_core::{service::error::ServiceError, transport_protocol::TransportProtocolError};

#[utoipa::path(
    post,
    path = "/ssi/temporary-verifier/v1/connect",
    request_body = ConnectRequestRestDTO,
    responses(
        (status = 200, description = "OK", body = ConnectVerifierResponseRestDTO),
        (status = 400, description = "Invalid request"),
        (status = 404, description = "Proof not found"),
        (status = 409, description = "Invalid proof state"),
        (status = 500, description = "Server error"),
    ),
    params(
        PostSsiVerifierConnectQueryParams
    ),
    tag = "ssi",
)]
pub(crate) async fn ssi_verifier_connect(
    state: State<AppState>,
    Query(query): Query<PostSsiVerifierConnectQueryParams>,
    Json(request): Json<ConnectRequestRestDTO>,
) -> Response {
    let result = state
        .core
        .ssi_verifier_service
        .connect_to_holder(&query.proof, &request.did)
        .await;

    match result {
        Ok(result) => (
            StatusCode::OK,
            Json(ConnectVerifierResponseRestDTO::from(result)),
        )
            .into_response(),
        Err(ServiceError::AlreadyExists) => {
            tracing::warn!("Already finished");
            (StatusCode::CONFLICT, "Already finished").into_response()
        }
        Err(ServiceError::IncorrectParameters) => {
            tracing::warn!("Wrong parameters");
            (StatusCode::BAD_REQUEST, "Wrong parameters").into_response()
        }
        Err(ServiceError::NotFound) => {
            tracing::error!("Missing proof");
            (StatusCode::NOT_FOUND, "Missing proof").into_response()
        }
        Err(e) => {
            tracing::error!("Error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

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
        ProofRequestQueryParams
    ),
    tag = "ssi",
)]
pub(crate) async fn ssi_verifier_reject_proof(
    state: State<AppState>,
    Query(query): Query<ProofRequestQueryParams>,
) -> Response {
    let result = state
        .core
        .ssi_verifier_service
        .reject_proof(&query.proof)
        .await;

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
        ProofRequestQueryParams
    ),
    tag = "ssi",
)]
pub(crate) async fn ssi_verifier_submit_proof(
    state: State<AppState>,
    Query(query): Query<ProofRequestQueryParams>,
    request: String,
) -> Response {
    let result = state
        .core
        .ssi_verifier_service
        .submit_proof(&query.proof, &request)
        .await;

    match result {
        Ok(_) => (StatusCode::NO_CONTENT).into_response(),
        Err(ServiceError::AlreadyExists) => {
            tracing::warn!("Already finished");
            (StatusCode::CONFLICT, "Already finished").into_response()
        }
        Err(ServiceError::NotFound) => {
            tracing::error!("Missing proof");
            (StatusCode::NOT_FOUND, "Missing proof").into_response()
        }
        Err(ServiceError::IncorrectParameters) => {
            tracing::error!("Wrong arguments");
            (StatusCode::BAD_REQUEST, "Wrong arguments").into_response()
        }
        Err(e) => {
            tracing::error!("Error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    post,
    path = "/ssi/temporary-issuer/v1/connect",
    request_body = ConnectRequestRestDTO,
    responses(
        (status = 200, description = "OK", body = ConnectIssuerResponseRestDTO),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Server error"),
    ),
    params(
        PostSsiIssuerConnectQueryParams
    ),
    tag = "ssi",
)]
pub(crate) async fn ssi_issuer_connect(
    state: State<AppState>,
    Query(query): Query<PostSsiIssuerConnectQueryParams>,
    Json(request): Json<ConnectRequestRestDTO>,
) -> Response {
    let result = state
        .core
        .ssi_issuer_service
        .issuer_connect(&query.credential, &request.did)
        .await;

    match result {
        Ok(result) => (
            StatusCode::OK,
            Json(ConnectIssuerResponseRestDTO::from(result)),
        )
            .into_response(),
        Err(ServiceError::AlreadyExists) => {
            tracing::error!("Already issued");
            (StatusCode::CONFLICT, "Already issued").into_response()
        }
        Err(ServiceError::NotFound) => {
            tracing::error!("Missing credential");
            (StatusCode::NOT_FOUND, "Missing credential").into_response()
        }
        Err(ServiceError::IncorrectParameters) => {
            tracing::error!("Invalid arguments");
            (StatusCode::BAD_REQUEST, "Invalid arguments").into_response()
        }
        Err(e) => {
            tracing::error!("Error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    post,
    path = "/ssi/handle-invitation/v1",
    request_body = HandleInvitationRequestRestDTO,
    responses(
        (status = 200, description = "OK", body = HandleInvitationResponseRestDTO),
        (status = 400, description = "Url missing"),
    ),
    tag = "ssi"
)]
pub(crate) async fn ssi_holder_handle_invitation(
    state: State<AppState>,
    Json(request): Json<HandleInvitationRequestRestDTO>,
) -> Response {
    let result = state
        .core
        .ssi_holder_service
        .handle_invitation(&request.url, &request.did_id)
        .await;

    match result {
        Ok(result) => (
            StatusCode::OK,
            Json(HandleInvitationResponseRestDTO::from(result)),
        )
            .into_response(),
        Err(ServiceError::TransportProtocolError(TransportProtocolError::HttpRequestError(
            error,
        ))) => {
            tracing::error!("HTTP request error: {:?}", error);
            StatusCode::BAD_GATEWAY.into_response()
        }
        Err(ServiceError::TransportProtocolError(TransportProtocolError::JsonError(error))) => {
            tracing::error!("JSON parsing error: {:?}", error);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(ServiceError::IncorrectParameters) => {
            tracing::error!("Invalid parameters: {:?}", result);
            StatusCode::BAD_REQUEST.into_response()
        }
        Err(error) => {
            tracing::error!("Unknown error: {:?}", error);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
