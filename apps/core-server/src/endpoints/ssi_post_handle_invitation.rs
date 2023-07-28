use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use one_core::error::{OneCoreError, SSIError};
use one_core::transport_protocol::TransportProtocolError;

use crate::{data_model::HandleInvitationRequestDTO, AppState};

#[utoipa::path(
    post,
    path = "/ssi/handle-invitation/v1",
    request_body = HandleInvitationRequestDTO,
    responses(
        (status = 200, description = "OK"),
        (status = 400, description = "Url missing"),
    ),
    tag = "ssi"
)]
pub(crate) async fn ssi_post_handle_invitation(
    state: State<AppState>,
    Json(request): Json<HandleInvitationRequestDTO>,
) -> Response {
    let result = state.core.handle_invitation(&request.url).await;

    match result {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(OneCoreError::SSIError(SSIError::TransportProtocolError(
            TransportProtocolError::HttpRequestError(error),
        ))) => {
            tracing::error!("HTTP request error: {:?}", error);
            StatusCode::BAD_GATEWAY.into_response()
        }
        Err(OneCoreError::SSIError(SSIError::TransportProtocolError(
            TransportProtocolError::JsonError(error),
        ))) => {
            tracing::error!("JSON parsing error: {:?}", error);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(OneCoreError::DataLayerError(error)) => {
            tracing::error!("DataLayer error: {:?}", error);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(error) => {
            tracing::error!("Unknown error: {:?}", error);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
