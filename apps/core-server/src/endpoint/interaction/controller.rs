use super::dto::{
    HandleInvitationRequestRestDTO, HandleInvitationResponseRestDTO, IssuanceRejectRequestRestDTO,
    IssuanceSubmitRequestRestDTO, PresentationRejectRequestRestDTO,
    PresentationSubmitRequestRestDTO,
};
use crate::AppState;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use one_core::{service::error::ServiceError, transport_protocol::TransportProtocolError};

#[utoipa::path(
    post,
    path = "/api/interaction/v1/handle-invitation",
    request_body = HandleInvitationRequestRestDTO,
    responses(
        (status = 200, description = "OK", body = HandleInvitationResponseRestDTO),
        (status = 400, description = "Url missing"),
    ),
    tag = "interaction",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn handle_invitation(
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
        Err(ServiceError::IncorrectParameters) => {
            tracing::error!("Invalid parameters: {:?}", result);
            StatusCode::BAD_REQUEST.into_response()
        }
        Err(ServiceError::TransportProtocolError(TransportProtocolError::JsonError(error))) => {
            tracing::error!("JSON parsing error: {:?}", error);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(error) => {
            tracing::error!("Unknown error: {:?}", error);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/interaction/v1/issuance-submit",
    request_body = IssuanceSubmitRequestRestDTO,
    responses(
        (status = 204, description = "No content"),
        (status = 404, description = "Not found"),
        (status = 409, description = "Invalid state"),
    ),
    tag = "interaction",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn issuance_submit(
    state: State<AppState>,
    Json(request): Json<IssuanceSubmitRequestRestDTO>,
) -> Response {
    let result = state
        .core
        .ssi_holder_service
        .accept_credential(&request.interaction_id)
        .await;

    match result {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(ServiceError::TransportProtocolError(TransportProtocolError::HttpRequestError(
            error,
        ))) => {
            tracing::error!("HTTP request error: {:?}", error);
            StatusCode::BAD_GATEWAY.into_response()
        }
        Err(ServiceError::NotFound) => {
            tracing::error!("Credential offer not found: {:?}", result);
            StatusCode::NOT_FOUND.into_response()
        }
        Err(ServiceError::AlreadyExists) => {
            tracing::error!("Wrong state: {:?}", result);
            StatusCode::CONFLICT.into_response()
        }
        Err(error) => {
            tracing::error!("Unknown error: {:?}", error);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/interaction/v1/issuance-reject",
    request_body = IssuanceRejectRequestRestDTO,
    responses(
        (status = 204, description = "No content"),
        (status = 404, description = "Not found"),
        (status = 409, description = "Invalid state"),
    ),
    tag = "interaction",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn issuance_reject(
    state: State<AppState>,
    Json(request): Json<IssuanceRejectRequestRestDTO>,
) -> Response {
    let result = state
        .core
        .ssi_holder_service
        .reject_credential(&request.interaction_id)
        .await;

    match result {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(ServiceError::TransportProtocolError(TransportProtocolError::HttpRequestError(
            error,
        ))) => {
            tracing::error!("HTTP request error: {:?}", error);
            StatusCode::BAD_GATEWAY.into_response()
        }
        Err(ServiceError::NotFound) => {
            tracing::error!("Credential offer not found: {:?}", result);
            StatusCode::NOT_FOUND.into_response()
        }
        Err(ServiceError::AlreadyExists) => {
            tracing::error!("Wrong state: {:?}", result);
            StatusCode::CONFLICT.into_response()
        }
        Err(error) => {
            tracing::error!("Unknown error: {:?}", error);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/interaction/v1/presentation-reject",
    request_body = PresentationRejectRequestRestDTO,
    responses(
        (status = 204, description = "No content"),
        (status = 404, description = "Not found"),
        (status = 409, description = "Invalid state"),
    ),
    tag = "interaction",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn presentation_reject(
    state: State<AppState>,
    Json(request): Json<PresentationRejectRequestRestDTO>,
) -> Response {
    let result = state
        .core
        .ssi_holder_service
        .reject_proof_request(&request.interaction_id)
        .await;

    match result {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(ServiceError::TransportProtocolError(TransportProtocolError::HttpRequestError(
            error,
        ))) => {
            tracing::error!("HTTP request error: {:?}", error);
            StatusCode::BAD_GATEWAY.into_response()
        }
        Err(ServiceError::NotFound) => {
            tracing::error!("Proof request not found: {:?}", result);
            StatusCode::NOT_FOUND.into_response()
        }
        Err(ServiceError::AlreadyExists) => {
            tracing::error!("Wrong state: {:?}", result);
            StatusCode::CONFLICT.into_response()
        }
        Err(error) => {
            tracing::error!("Unknown error: {:?}", error);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/interaction/v1/presentation-submit",
    request_body = PresentationSubmitRequestRestDTO,
    responses(
        (status = 204, description = "No content"),
        (status = 404, description = "Not found"),
        (status = 409, description = "Invalid state"),
    ),
    tag = "interaction",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn presentation_submit(
    state: State<AppState>,
    Json(request): Json<PresentationSubmitRequestRestDTO>,
) -> Response {
    let result = state
        .core
        .ssi_holder_service
        .submit_proof(request.into())
        .await;

    match result {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(ServiceError::TransportProtocolError(TransportProtocolError::HttpRequestError(
            error,
        ))) => {
            tracing::error!("HTTP request error: {:?}", error);
            StatusCode::BAD_GATEWAY.into_response()
        }
        Err(ServiceError::NotFound) => {
            tracing::error!("Proof request not found: {:?}", result);
            StatusCode::NOT_FOUND.into_response()
        }
        Err(ServiceError::AlreadyExists) => {
            tracing::error!("Wrong state: {:?}", result);
            StatusCode::CONFLICT.into_response()
        }
        Err(error) => {
            tracing::error!("Unknown error: {:?}", error);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
