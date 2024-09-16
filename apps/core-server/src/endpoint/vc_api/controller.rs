use axum::extract::{Path, State};
use axum::Json;
use axum_extra::extract::WithRejection;
use one_core::service::error::{MissingProviderError, ServiceError};
use one_providers::did::error::DidMethodProviderError;
use shared_types::DidValue;

use super::dto::{
    CredentialIssueRequestDto, CredentialIssueResponseDto, CredentialVerifiyRequestDto,
    CredentialVerifyResponseDto, DidDocumentResolutionResponseDto, PresentationVerifyRequestDto,
    PresentationVerifyResponseDto,
};
use super::response::VcApiErrorResponseRestDTO;
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{CreatedOrErrorResponse, OkOrErrorResponse};
use crate::endpoint::vc_api::response::VcApiResponse;
use crate::router::AppState;

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

#[tracing::instrument(level = "debug", skip(state))]
#[utoipa::path(
    get,
    path = "/vc-api/identifiers/{identifier}",
    responses(VcApiResponse<DidDocumentResolutionResponseDto>),
    params(
        ("identifier" = String, Path, description = "Identifier")
    ),
    tag = "vc_interop_testing",
)]
pub(crate) async fn resolve_identifier(
    state: State<AppState>,
    WithRejection(Path(did_value), _): WithRejection<Path<DidValue>, VcApiErrorResponseRestDTO>,
) -> VcApiResponse<DidDocumentResolutionResponseDto> {
    let result = state
        .core
        .did_service
        .resolve_did(&did_value)
        .await
        .map_err(|e| match e {
            DidMethodProviderError::MissingProvider(e) => {
                ServiceError::MissingProvider(MissingProviderError::DidMethod(e))
            }
            _ => ServiceError::DidMethodProviderError(e),
        });

    VcApiResponse::from_result(result)
}
