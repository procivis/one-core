use axum::extract::State;
use axum::Json;
use axum_extra::extract::WithRejection;

use crate::dto::response::CreatedOrErrorResponse;
use crate::dto::{error::ErrorResponseRestDTO, response::OkOrErrorResponse};
use crate::router::AppState;

use super::dto::{
    CredentialIssueRequestDto, CredentialIssueResponseDto, CredentialVerifiyRequestDto,
    CredentialVerifyResponseDto, PresentationVerifyRequestDto, PresentationVerifyResponseDto,
};

#[tracing::instrument(level = "debug", skip(state))]
#[tracing::instrument(level = "debug", skip(state))]
#[utoipa::path(
    post,
    path = "/vc-api/credentials/issue",
    request_body = CredentialIssueRequestDto,
    responses(CreatedOrErrorResponse<CredentialIssueResponseDto>),
    tag = "vc_interop_testing",
)]
pub(crate) async fn issue_credential(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<CredentialIssueRequestDto>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<CredentialIssueResponseDto> {
    let issued = state
        .core
        .vc_api_service
        .issue_credential(request.into())
        .await;

    match issued {
        Ok(value) => OkOrErrorResponse::Ok(value.into()),
        Err(error) => {
            tracing::error!("issuance error: {:?}", error);
            OkOrErrorResponse::from_service_error(error, state.config.hide_error_response_cause)
        }
    }
}

#[tracing::instrument(level = "debug", skip(state))]
#[utoipa::path(
    post,
    path = "/vc-api/credentials/verify",
    request_body = CredentialVerifiyRequestDto,
    responses(CreatedOrErrorResponse<CredentialVerifyResponseDto>),
    tag = "vc_interop_testing",
)]
pub(crate) async fn verify_credential(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<CredentialVerifiyRequestDto>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<CredentialVerifyResponseDto> {
    match state
        .core
        .vc_api_service
        .verify_credential(request.into())
        .await
    {
        Ok(value) => OkOrErrorResponse::ok(value),
        Err(error) => {
            tracing::error!("verification error: {:?}", error);
            OkOrErrorResponse::from_service_error(error, state.config.hide_error_response_cause)
        }
    }
}

#[tracing::instrument(level = "debug", skip(state))]
#[utoipa::path(
    post,
    path = "/vc-api/presentations/verify",
    request_body = PresentationVerifiyRequestDto,
    responses(CreatedOrErrorResponse<PresentationVerifyResponseDto>),
    tag = "vc_interop_testing",
)]
pub(crate) async fn verify_presentation(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<PresentationVerifyRequestDto>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<PresentationVerifyResponseDto> {
    match state
        .core
        .vc_api_service
        .verify_presentation(request.into())
        .await
    {
        Ok(value) => OkOrErrorResponse::ok(value),
        Err(error) => {
            tracing::error!("verification error: {:?}", error);
            OkOrErrorResponse::from_service_error(error, state.config.hide_error_response_cause)
        }
    }
}
