use std::sync::Arc;

use super::dto::{
    HandleInvitationRequestRestDTO, HandleInvitationResponseRestDTO, IssuanceRejectRequestRestDTO,
    IssuanceSubmitRequestRestDTO, PresentationRejectRequestRestDTO,
    PresentationSubmitRequestRestDTO,
};
use crate::{dto::common::EmptyOrErrorResponse, router::AppState, ServerConfig};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};

use one_core::{
    provider::transport_protocol::TransportProtocolError, service::error::ServiceError,
};

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
        .handle_invitation(request.url, &request.did_id)
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
    responses(EmptyOrErrorResponse),
    tag = "interaction",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn issuance_submit(
    config: Extension<Arc<ServerConfig>>,
    state: State<AppState>,
    Json(request): Json<IssuanceSubmitRequestRestDTO>,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .ssi_holder_service
        .accept_credential(&request.interaction_id)
        .await;

    match result {
        Ok(_) => EmptyOrErrorResponse::NoContent,
        Err(error) => {
            tracing::error!(%error, "Error while accepting credential");
            EmptyOrErrorResponse::from_service_error(error, config.hide_error_response_cause)
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/interaction/v1/issuance-reject",
    request_body = IssuanceRejectRequestRestDTO,
    responses(EmptyOrErrorResponse),
    tag = "interaction",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn issuance_reject(
    config: Extension<Arc<ServerConfig>>,
    state: State<AppState>,
    Json(request): Json<IssuanceRejectRequestRestDTO>,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .ssi_holder_service
        .reject_credential(&request.interaction_id)
        .await;

    match result {
        Ok(_) => EmptyOrErrorResponse::NoContent,
        Err(error) => {
            tracing::error!(%error, "Error while rejecting credential");
            EmptyOrErrorResponse::from_service_error(error, config.hide_error_response_cause)
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/interaction/v1/presentation-reject",
    request_body = PresentationRejectRequestRestDTO,
    responses(EmptyOrErrorResponse),
    tag = "interaction",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn presentation_reject(
    config: Extension<Arc<ServerConfig>>,
    state: State<AppState>,
    Json(request): Json<PresentationRejectRequestRestDTO>,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .ssi_holder_service
        .reject_proof_request(&request.interaction_id)
        .await;

    match result {
        Ok(_) => EmptyOrErrorResponse::NoContent,
        Err(error) => {
            tracing::error!(%error, "Error while rejecting proof request");
            EmptyOrErrorResponse::from_service_error(error, config.hide_error_response_cause)
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/interaction/v1/presentation-submit",
    request_body = PresentationSubmitRequestRestDTO,
    responses(EmptyOrErrorResponse),
    tag = "interaction",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn presentation_submit(
    config: Extension<Arc<ServerConfig>>,
    state: State<AppState>,
    Json(request): Json<PresentationSubmitRequestRestDTO>,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .ssi_holder_service
        .submit_proof(request.into())
        .await;

    match result {
        Ok(_) => EmptyOrErrorResponse::NoContent,
        Err(error) => {
            tracing::error!(%error, "Error while submitting proof");
            EmptyOrErrorResponse::from_service_error(error, config.hide_error_response_cause)
        }
    }
}
