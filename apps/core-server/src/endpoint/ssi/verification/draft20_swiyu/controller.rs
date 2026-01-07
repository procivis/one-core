use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use axum_extra::extract::WithRejection;
use one_core::provider::verification_protocol::openid4vp::error::OpenID4VCError;
use one_core::provider::verification_protocol::openid4vp::model::OpenID4VPDirectPostRequestDTO;
use one_core::service::error::{BusinessLogicError, ServiceError};
use shared_types::InteractionId;

use super::super::super::dto::{OpenID4VCIErrorResponseRestDTO, OpenID4VCIErrorRestEnum};
use super::super::dto::{OpenID4VPDirectPostRequestRestDTO, OpenID4VPDirectPostResponseRestDTO};
use crate::dto::error::ErrorResponseRestDTO;
use crate::router::AppState;

#[utoipa::path(
    post,
    path = "/ssi/openid4vp/draft-20-swiyu/response/{id}",
    request_body(content = OpenID4VPDirectPostRequestRestDTO, description = "Verifier request", content_type = "application/x-www-form-urlencoded"
    ),
    params(
        ("id" = InteractionId, Path, description = "Interaction id")
    ),
    responses(
        (status = 200, description = "OK", body = OpenID4VPDirectPostResponseRestDTO),
        (status = 400, description = "OIDC Verifier errors", body = OpenID4VCIErrorResponseRestDTO),
        (status = 409, description = "Wrong proof state"),
        (status = 500, description = "Server error"),
    ),
    tag = "openid4vp-draft20-swiyu",
    summary = "OID4VC - Verifier direct post",
    description = indoc::formatdoc! {"
        This endpoint handles low-level mechanisms in interactions between agents.
        Deep understanding of the involved protocols is recommended.
    "},
)]
pub(crate) async fn oid4vp_draft20_swiyu_direct_post(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<InteractionId>, ErrorResponseRestDTO>,
    WithRejection(Form(request), _): WithRejection<
        Form<OpenID4VPDirectPostRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> Response {
    let mut request: OpenID4VPDirectPostRequestDTO = request.into();
    request.state = Some(id);
    let result = state.core.oid4vp_draft20_service.direct_post(request).await;

    match result {
        Ok(value) => (
            StatusCode::OK,
            Json(OpenID4VPDirectPostResponseRestDTO::from(value)),
        )
            .into_response(),
        Err(ServiceError::OpenID4VCError(OpenID4VCError::ValidationError(error))) => {
            tracing::error!("OpenID4VC validation error: {:?}", error);
            (
                StatusCode::BAD_REQUEST,
                Json(OpenID4VCIErrorResponseRestDTO {
                    error: OpenID4VCIErrorRestEnum::InvalidRequest,
                }),
            )
                .into_response()
        }
        Err(ServiceError::OpenID4VCError(OpenID4VCError::InvalidRequest)) => {
            tracing::error!("OpenID4VC invalid request");
            (
                StatusCode::BAD_REQUEST,
                Json(OpenID4VCIErrorResponseRestDTO {
                    error: OpenID4VCIErrorRestEnum::InvalidRequest,
                }),
            )
                .into_response()
        }
        Err(ServiceError::ConfigValidationError(error)) => {
            tracing::error!("Config validation error: {error}");
            StatusCode::NOT_FOUND.into_response()
        }
        Err(ServiceError::BusinessLogic(BusinessLogicError::CredentialIsRevokedOrSuspended)) => {
            tracing::error!("Credential is revoked or suspended");
            (
                StatusCode::BAD_REQUEST,
                "Credential is revoked or suspended",
            )
                .into_response()
        }
        Err(ServiceError::BusinessLogic(BusinessLogicError::MissingProofForInteraction(_))) => {
            tracing::error!("Missing interaction or proof");
            (StatusCode::BAD_REQUEST, "Missing interaction of proof").into_response()
        }
        Err(e) => {
            tracing::error!("Error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
