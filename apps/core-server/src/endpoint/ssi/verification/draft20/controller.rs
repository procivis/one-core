use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use axum_extra::extract::WithRejection;
use one_core::provider::verification_protocol::openid4vp::error::OpenID4VCError;
use one_core::service::error::{BusinessLogicError, ServiceError};
use shared_types::ProofId;

use super::super::super::dto::{OpenID4VCIErrorResponseRestDTO, OpenID4VCIErrorRestEnum};
use super::dto::{
    OpenID4VPClientMetadataResponseRestDTO, OpenID4VPDirectPostRequestRestDTO,
    OpenID4VPDirectPostResponseRestDTO, OpenID4VPPresentationDefinitionResponseRestDTO,
};
use crate::dto::error::ErrorResponseRestDTO;
use crate::router::AppState;

#[utoipa::path(
    post,
    path = "/ssi/openid4vp/draft-20/response",
    request_body(content = OpenID4VPDirectPostRequestRestDTO, description = "Verifier request", content_type = "application/x-www-form-urlencoded"
    ),
    responses(
        (status = 200, description = "OK", body = OpenID4VPDirectPostResponseRestDTO),
        (status = 400, description = "OIDC Verifier errors", body = OpenID4VCIErrorResponseRestDTO),
        (status = 409, description = "Wrong proof state"),
        (status = 500, description = "Server error"),
    ),
    tag = "openid4vp-draft20",
    summary = "OID4VC - Verifier direct post",
    description = indoc::formatdoc! {"
        This endpoint handles low-level mechanisms in interactions between agents.
        Deep understanding of the involved protocols is recommended.
    "},
)]
pub(crate) async fn oid4vp_draft20_direct_post(
    state: State<AppState>,
    WithRejection(Form(request), _): WithRejection<
        Form<OpenID4VPDirectPostRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> Response {
    let result = state
        .core
        .oid4vp_draft20_service
        .direct_post(request.into())
        .await;

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

#[utoipa::path(
    get,
    path = "/ssi/openid4vp/draft-20/{id}/presentation-definition",
    params(
        ("id" = ProofId, Path, description = "Proof id")
    ),
    responses(
        (status = 200, description = "OK", body = OpenID4VPPresentationDefinitionResponseRestDTO),
        (status = 400, description = "OIDC Verifier errors", body = OpenID4VCIErrorResponseRestDTO),
        (status = 404, description = "Proof does not exist"),
        (status = 500, description = "Server error"),
    ),
    tag = "openid4vp-draft20",
    summary = "OID4VC - Verifier presentation definition",
    description = indoc::formatdoc! {"
        This endpoint handles low-level mechanisms in interactions between agents.
        Deep understanding of the involved protocols is recommended.
    "},
)]
pub(crate) async fn oid4vp_draft20_presentation_definition(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<ProofId>, ErrorResponseRestDTO>,
) -> Response {
    let result = state
        .core
        .oid4vp_draft20_service
        .presentation_definition(id)
        .await;

    match result {
        Ok(value) => (
            StatusCode::OK,
            Json(OpenID4VPPresentationDefinitionResponseRestDTO::from(value)),
        )
            .into_response(),
        Err(ServiceError::ConfigValidationError(error)) => {
            tracing::error!("Config validation error: {error}");
            (
                StatusCode::BAD_REQUEST,
                Json(OpenID4VCIErrorResponseRestDTO {
                    error: OpenID4VCIErrorRestEnum::InvalidRequest,
                }),
            )
                .into_response()
        }
        Err(ServiceError::BusinessLogic(BusinessLogicError::InvalidProofState { .. })) => (
            StatusCode::BAD_REQUEST,
            Json(OpenID4VCIErrorResponseRestDTO {
                error: OpenID4VCIErrorRestEnum::InvalidRequest,
            }),
        )
            .into_response(),
        Err(ServiceError::EntityNotFound(_)) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!("Error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    get,
    path = "/ssi/openid4vp/draft-20/{id}/client-metadata",
    params(
        ("id" = ProofId, Path, description = "Proof id")
    ),
    responses(
        (status = 200, description = "OK", body = OpenID4VPClientMetadataResponseRestDTO),
        (status = 400, description = "OIDC Verifier errors", body = OpenID4VCIErrorResponseRestDTO),
        (status = 404, description = "Proof does not exist"),
        (status = 500, description = "Server error"),
    ),
    tag = "openid4vp-draft20",
    summary = "OID4VC - Client metadata",
    description = indoc::formatdoc! {"
        This endpoint handles low-level mechanisms in interactions between agents.
        Deep understanding of the involved protocols is recommended.
    "},
)]
pub(crate) async fn oid4vp_draft20_client_metadata(
    state: State<AppState>,
    WithRejection(Path(proof_id), _): WithRejection<Path<ProofId>, ErrorResponseRestDTO>,
) -> Response {
    let result = state
        .core
        .oid4vp_draft20_service
        .get_client_metadata(proof_id)
        .await;

    match result {
        Ok(value) => (
            StatusCode::OK,
            Json(OpenID4VPClientMetadataResponseRestDTO::from(value)),
        )
            .into_response(),
        Err(ServiceError::ConfigValidationError(error)) => {
            tracing::error!("Config validation error: {error}");
            (
                StatusCode::BAD_REQUEST,
                Json(OpenID4VCIErrorResponseRestDTO {
                    error: OpenID4VCIErrorRestEnum::InvalidRequest,
                }),
            )
                .into_response()
        }
        Err(error @ ServiceError::BusinessLogic(BusinessLogicError::InvalidProofState { .. })) => {
            tracing::error!("BAD_REQUEST validation error: {error}");
            (
                StatusCode::BAD_REQUEST,
                Json(OpenID4VCIErrorResponseRestDTO {
                    error: OpenID4VCIErrorRestEnum::InvalidRequest,
                }),
            )
                .into_response()
        }
        Err(ServiceError::EntityNotFound(_)) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!("Error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    get,
    path = "/ssi/openid4vp/draft-20/{id}/client-request",
    params(
        ("id" = ProofId, Path, description = "Proof id")
    ),
    responses(
        (status = 200, description = "OK", body = String, content_type = "application/oauth-authz-req+jwt"),
        (status = 400, description = "OIDC Verifier errors", body = OpenID4VCIErrorResponseRestDTO),
        (status = 404, description = "Proof does not exist"),
        (status = 500, description = "Server error"),
    ),
    tag = "openid4vp-draft20",
    summary = "OID4VC - Proof request data",
    description = indoc::formatdoc! {"
        This endpoint handles an aspect of the SSI interactions between agents and should **not** be used.
        For information on this endpoint, see directly the [OpenID for Verifiable Credentials
        specifications](https://openid.net/sg/openid4vc/specifications/).
    "},
)]
pub(crate) async fn oid4vp_draft20_client_request(
    state: State<AppState>,
    WithRejection(Path(proof_id), _): WithRejection<Path<ProofId>, ErrorResponseRestDTO>,
) -> Response {
    let result = state
        .core
        .oid4vp_draft20_service
        .get_client_request(proof_id)
        .await;

    match result {
        Ok(jwt) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/oauth-authz-req+jwt")],
            jwt,
        )
            .into_response(),
        Err(ServiceError::ConfigValidationError(error)) => {
            tracing::error!("Config validation error: {error}");
            (
                StatusCode::BAD_REQUEST,
                Json(OpenID4VCIErrorResponseRestDTO {
                    error: OpenID4VCIErrorRestEnum::InvalidRequest,
                }),
            )
                .into_response()
        }
        Err(error @ ServiceError::BusinessLogic(BusinessLogicError::InvalidProofState { .. })) => {
            tracing::error!("BAD_REQUEST validation error: {error}");
            (
                StatusCode::BAD_REQUEST,
                Json(OpenID4VCIErrorResponseRestDTO {
                    error: OpenID4VCIErrorRestEnum::InvalidRequest,
                }),
            )
                .into_response()
        }
        Err(ServiceError::EntityNotFound(_)) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!("Error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
