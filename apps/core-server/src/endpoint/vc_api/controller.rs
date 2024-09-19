use axum::extract::{Path, State};
use axum::Json;
use axum_extra::extract::WithRejection;
use one_core::provider::did_method::error::DidMethodProviderError;
use one_core::service::error::{MissingProviderError, ServiceError};
use shared_types::DidValue;

use super::dto::{
    CredentialIssueRequestDto, CredentialIssueResponseDTO, CredentialVerifiyRequestDto,
    CredentialVerifyResponseDto, DidDocumentResolutionResponseDTO, PresentationVerifyRequestDto,
    PresentationVerifyResponseDto,
};
use super::error::VcApiError;
use crate::endpoint::vc_api::response::VcApiResponse;
use crate::router::AppState;

#[tracing::instrument(level = "debug", skip(state))]
#[utoipa::path(
    post,
    path = "/vc-api/credentials/issue",
    request_body = CredentialIssueRequestDto,
    responses(VcApiResponse<CredentialIssueResponseDTO>),
    tag = "vc_interop_testing",
)]
pub(crate) async fn issue_credential(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<Json<CredentialIssueRequestDto>, VcApiError>,
) -> VcApiResponse<CredentialIssueResponseDTO> {
    let issued = state
        .core
        .vc_api_service
        .issue_credential(request.into())
        .await;

    VcApiResponse::created(issued)
}

#[tracing::instrument(level = "debug", skip(state))]
#[utoipa::path(
    post,
    path = "/vc-api/credentials/verify",
    request_body = CredentialVerifiyRequestDto,
    responses(VcApiResponse<CredentialVerifyResponseDto>),
    tag = "vc_interop_testing",
)]
pub(crate) async fn verify_credential(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<Json<CredentialVerifiyRequestDto>, VcApiError>,
) -> VcApiResponse<CredentialVerifyResponseDto> {
    let result = state
        .core
        .vc_api_service
        .verify_credential(request.into())
        .await;

    VcApiResponse::ok(result)
}

#[tracing::instrument(level = "debug", skip(state))]
#[utoipa::path(
    post,
    path = "/vc-api/presentations/verify",
    request_body = PresentationVerifiyRequestDto,
    responses(VcApiResponse<PresentationVerifyResponseDto>),
    tag = "vc_interop_testing",
)]
pub(crate) async fn verify_presentation(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<Json<PresentationVerifyRequestDto>, VcApiError>,
) -> VcApiResponse<PresentationVerifyResponseDto> {
    let result = state
        .core
        .vc_api_service
        .verify_presentation(request.into())
        .await;

    VcApiResponse::ok(result)
}

#[tracing::instrument(level = "debug", skip(state))]
#[utoipa::path(
    get,
    path = "/vc-api/identifiers/{identifier}",
    responses(VcApiResponse<DidDocumentResolutionResponseDTO>),
    params(
        ("identifier" = String, Path, description = "Identifier")
    ),
    tag = "vc_interop_testing",
)]
pub(crate) async fn resolve_identifier(
    state: State<AppState>,
    WithRejection(Path(did_value), _): WithRejection<Path<DidValue>, VcApiError>,
) -> VcApiResponse<DidDocumentResolutionResponseDTO> {
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

    VcApiResponse::ok(result)
}
