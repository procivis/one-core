use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use axum_extra::extract::WithRejection;
use axum_extra::typed_header::TypedHeader;
use headers::authorization::Bearer;
use one_core::provider::issuance_protocol::error::IssuanceProtocolError;
use one_core::service::error::{EntityNotFoundError, ServiceError};
use shared_types::{CredentialId, CredentialSchemaId};

use super::dto::{
    OpenID4VCICredentialOfferRestDTO, OpenID4VCICredentialRequestRestDTO,
    OpenID4VCICredentialResponseRestDTO, OpenID4VCIDiscoveryResponseRestDTO,
    OpenID4VCIErrorResponseRestDTO, OpenID4VCIErrorRestEnum,
    OpenID4VCIIssuerMetadataResponseRestDTO, OpenID4VCINonceResponseRestDTO,
    OpenID4VCINotificationRequestRestDTO, OpenID4VCITokenRequestRestDTO,
    OpenID4VCITokenResponseRestDTO,
};
use crate::dto::error::ErrorResponseRestDTO;
use crate::router::AppState;

#[utoipa::path(
    get,
    path = "/ssi/openid4vci/final-1.0/{id}/.well-known/openid-credential-issuer",
    params(
        ("id" = CredentialSchemaId, Path, description = "Credential schema id")
    ),
    responses(
        (status = 200, description = "OK", body = OpenID4VCIIssuerMetadataResponseRestDTO),
        (status = 404, description = "Credential schema not found"),
        (status = 500, description = "Server error"),
    ),
    tag = "openid4vci-final1_0",
    summary = "OID4VC - Retrieve issuer metadata",
    description = indoc::formatdoc! {"
        This endpoint handles low-level mechanisms in interactions between agents.
        Deep understanding of the involved protocols is recommended.
    "},
)]
pub(crate) async fn oid4vci_final1_0_get_issuer_metadata(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<CredentialSchemaId>, ErrorResponseRestDTO>,
) -> Response {
    let result = state
        .core
        .oid4vci_final1_0_service
        .get_issuer_metadata(&id)
        .await;

    match result {
        Ok(value) => (
            StatusCode::OK,
            Json(OpenID4VCIIssuerMetadataResponseRestDTO::from(value)),
        )
            .into_response(),
        Err(ServiceError::ConfigValidationError(error)) => {
            tracing::error!("Config validation error: {error}");
            StatusCode::NOT_FOUND.into_response()
        }
        Err(ServiceError::EntityNotFound(EntityNotFoundError::CredentialSchema(_))) => {
            tracing::error!("Missing credential schema");
            (StatusCode::NOT_FOUND, "Missing credential schema").into_response()
        }
        Err(e) => {
            tracing::error!("Error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    get,
    path = "/.well-known/openid-configuration/ssi/openid4vci/final-1.0/{id}",
    params(
        ("id" = CredentialSchemaId, Path, description = "Credential schema id")
    ),
    responses(
        (status = 200, description = "OK", body = OpenID4VCIDiscoveryResponseRestDTO),
        (status = 404, description = "Credential schema not found"),
        (status = 500, description = "Server error"),
    ),
    tag = "openid4vci-final1_0",
    summary = "OID4VC - Service discovery",
    description = indoc::formatdoc! {"
        This endpoint handles low-level mechanisms in interactions between agents.
        Deep understanding of the involved protocols is recommended.
    "},
)]
pub(crate) async fn oid4vci_final1_0_service_discovery(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<CredentialSchemaId>, ErrorResponseRestDTO>,
) -> Response {
    let result = state
        .core
        .oid4vci_final1_0_service
        .service_discovery(&id)
        .await;

    match result {
        Ok(value) => (
            StatusCode::OK,
            Json(OpenID4VCIDiscoveryResponseRestDTO::from(value)),
        )
            .into_response(),
        Err(ServiceError::ConfigValidationError(error)) => {
            tracing::error!("Config validation error: {error}");
            StatusCode::NOT_FOUND.into_response()
        }
        Err(ServiceError::EntityNotFound(EntityNotFoundError::CredentialSchema(_))) => {
            tracing::error!("Missing credential schema");
            (StatusCode::NOT_FOUND, "Missing credential schema").into_response()
        }
        Err(e) => {
            tracing::error!("Error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    get,
    path = "/ssi/openid4vci/final-1.0/{credential_schema_id}/offer/{credential_id}",
    params(
        ("credential_schema_id" = CredentialSchemaId, Path, description = "Credential schema id"),
        ("credential_id" = CredentialId, Path, description = "Credential id")
    ),
    responses(
        (status = 200, description = "OK", body = OpenID4VCICredentialOfferRestDTO),
        (status = 400, description = "Invalid request"),
        (status = 404, description = "Credential not found"),
        (status = 500, description = "Server error"),
    ),
    tag = "openid4vci-final1_0",
    summary = "OID4VC - Retrieve credential offer",
    description = indoc::formatdoc! {"
        This endpoint handles low-level mechanisms in interactions between agents.
        Deep understanding of the involved protocols is recommended.
    "},
)]
pub(crate) async fn oid4vci_final1_0_get_credential_offer(
    state: State<AppState>,
    WithRejection(Path((credential_schema_id, credential_id)), _): WithRejection<
        Path<(CredentialSchemaId, CredentialId)>,
        ErrorResponseRestDTO,
    >,
) -> Response {
    let result = state
        .core
        .oid4vci_final1_0_service
        .get_credential_offer(credential_schema_id, credential_id)
        .await;

    match result {
        Ok(value) => (
            StatusCode::OK,
            Json(OpenID4VCICredentialOfferRestDTO::from(value)),
        )
            .into_response(),
        Err(ServiceError::OpenID4VCIError(error)) => {
            tracing::error!("OpenID4VCI credential offer error: {:?}", error);
            (
                StatusCode::BAD_REQUEST,
                Json(OpenID4VCIErrorResponseRestDTO::from(error)),
            )
                .into_response()
        }
        Err(ServiceError::EntityNotFound(EntityNotFoundError::Credential(_))) => {
            tracing::error!("Missing credential");
            StatusCode::NOT_FOUND.into_response()
        }
        Err(e) => {
            tracing::error!("Error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    post,
    path = "/ssi/openid4vci/final-1.0/{id}/token",
    request_body(content = OpenID4VCITokenRequestRestDTO, description = "Token request", content_type = "application/x-www-form-urlencoded"
    ),
    params(
        ("id" = CredentialSchemaId, Path, description = "Credential schema id")
    ),
    responses(
        (status = 200, description = "OK", body = OpenID4VCITokenResponseRestDTO),
        (status = 400, description = "OIDC token errors", body = OpenID4VCIErrorResponseRestDTO),
        (status = 404, description = "Credential schema not found"),
        (status = 409, description = "Wrong credential state"),
        (status = 500, description = "Server error"),
    ),
    tag = "openid4vci-final1_0",
    summary = "OID4VC - Create token",
    description = indoc::formatdoc! {"
        This endpoint handles low-level mechanisms in interactions between agents.
        Deep understanding of the involved protocols is recommended.
    "},
)]
pub(crate) async fn oid4vci_final1_0_create_token(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<CredentialSchemaId>, ErrorResponseRestDTO>,
    WithRejection(Form(request), _): WithRejection<
        Form<OpenID4VCITokenRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> Response {
    let result = async {
        state
            .core
            .oid4vci_final1_0_service
            .create_token(&id, request.try_into()?)
            .await
    }
    .await;

    match result {
        Ok(value) => (
            StatusCode::OK,
            Json(OpenID4VCITokenResponseRestDTO::from(value)),
        )
            .into_response(),
        Err(ServiceError::OpenID4VCIError(error)) => {
            tracing::error!("OpenID4VCI token validation error: {:?}", error);
            (
                StatusCode::BAD_REQUEST,
                Json(OpenID4VCIErrorResponseRestDTO::from(error)),
            )
                .into_response()
        }
        Err(ServiceError::ConfigValidationError(error)) => {
            tracing::error!("Config validation error: {error}");
            StatusCode::NOT_FOUND.into_response()
        }
        Err(ServiceError::EntityNotFound(EntityNotFoundError::CredentialSchema(_))) => {
            tracing::error!("Missing credential schema");
            (StatusCode::NOT_FOUND, "Missing credential schema").into_response()
        }
        Err(e) => {
            tracing::error!("Error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    post,
    path = "/ssi/openid4vci/final-1.0/{id}/credential",
    request_body(content = OpenID4VCICredentialRequestRestDTO, description = "Credential request"),
    params(
        ("id" = CredentialSchemaId, Path, description = "Credential schema id")
    ),
    responses(
        (status = 200, description = "OK", body = OpenID4VCICredentialResponseRestDTO),
        (status = 400, description = "OIDC credential errors", body = OpenID4VCIErrorResponseRestDTO),
        (status = 404, description = "Credential schema not found"),
        (status = 409, description = "Wrong credential state"),
        (status = 500, description = "Server error"),
    ),
    security(
        ("openID4VCI" = [])
    ),
    tag = "openid4vci-final1_0",
    summary = "OID4VC - Create credential",
    description = indoc::formatdoc! {"
        This endpoint handles low-level mechanisms in interactions between agents.
        Deep understanding of the involved protocols is recommended.
    "},
)]
pub(crate) async fn oid4vci_final1_0_create_credential(
    state: State<AppState>,
    WithRejection(Path(credential_schema_id), _): WithRejection<
        Path<CredentialSchemaId>,
        ErrorResponseRestDTO,
    >,
    WithRejection(TypedHeader(token), _): WithRejection<
        TypedHeader<headers::Authorization<Bearer>>,
        ErrorResponseRestDTO,
    >,
    WithRejection(Json(request), _): WithRejection<
        Json<OpenID4VCICredentialRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> Response {
    let access_token = token.token();
    let result = state
        .core
        .oid4vci_final1_0_service
        .create_credential(&credential_schema_id, access_token, request.into())
        .await;

    match result {
        Ok(value) => (
            StatusCode::OK,
            Json(OpenID4VCICredentialResponseRestDTO::from(value)),
        )
            .into_response(),
        Err(ServiceError::OpenID4VCIError(error)) => {
            tracing::error!("OpenID4VCI credential validation error: {:?}", error);
            (
                StatusCode::BAD_REQUEST,
                Json(OpenID4VCIErrorResponseRestDTO::from(error)),
            )
                .into_response()
        }
        Err(ServiceError::IssuanceProtocolError(IssuanceProtocolError::RefreshTooSoon)) => {
            tracing::info!("Holder tried refreshing credential too soon");
            (
                StatusCode::BAD_REQUEST,
                Json(OpenID4VCIErrorResponseRestDTO {
                    error: OpenID4VCIErrorRestEnum::InvalidRequest,
                }),
            )
                .into_response()
        }
        Err(ServiceError::IssuanceProtocolError(IssuanceProtocolError::Suspended)) => {
            tracing::info!("Holder tried refreshing a suspended credential");
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
        Err(ServiceError::EntityNotFound(EntityNotFoundError::CredentialSchema(_))) => {
            tracing::error!("Missing credential schema");
            (StatusCode::NOT_FOUND, "Missing credential schema").into_response()
        }
        Err(e) => {
            tracing::error!("Error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    post,
    path = "/ssi/openid4vci/final-1.0/{id}/notification",
    request_body(content = OpenID4VCINotificationRequestRestDTO, description = "Notification request"),
    params(
        ("id" = CredentialSchemaId, Path, description = "Credential schema id")
    ),
    responses(
        (status = 204, description = "OK"),
        (status = 400, description = "OIDC credential errors", body = OpenID4VCIErrorResponseRestDTO),
        (status = 404, description = "Credential schema not found"),
        (status = 409, description = "Wrong credential state"),
        (status = 500, description = "Server error"),
    ),
    security(
        ("openID4VCI" = [])
    ),
    tag = "openid4vci-final1_0",
    summary = "OID4VC - Credential notification",
    description = indoc::formatdoc! {"
        This endpoint handles low-level mechanisms in interactions between agents.
        Deep understanding of the involved protocols is recommended.
    "},
)]
pub(crate) async fn oid4vci_final1_0_credential_notification(
    state: State<AppState>,
    WithRejection(Path(credential_schema_id), _): WithRejection<
        Path<CredentialSchemaId>,
        ErrorResponseRestDTO,
    >,
    WithRejection(TypedHeader(token), _): WithRejection<
        TypedHeader<headers::Authorization<Bearer>>,
        ErrorResponseRestDTO,
    >,
    WithRejection(Json(request), _): WithRejection<
        Json<OpenID4VCINotificationRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> Response {
    let access_token = token.token();
    let result = state
        .core
        .oid4vci_final1_0_service
        .handle_notification(&credential_schema_id, access_token, request.into())
        .await;

    match result {
        Ok(_) => (StatusCode::NO_CONTENT).into_response(),
        Err(ServiceError::OpenID4VCIError(error)) => {
            tracing::error!("OpenID4VCI credential notification error: {:?}", error);
            (
                StatusCode::BAD_REQUEST,
                Json(OpenID4VCIErrorResponseRestDTO::from(error)),
            )
                .into_response()
        }
        Err(ServiceError::ConfigValidationError(error)) => {
            tracing::error!("Config validation error: {error}");
            StatusCode::NOT_FOUND.into_response()
        }
        Err(ServiceError::EntityNotFound(EntityNotFoundError::CredentialSchema(_))) => {
            tracing::error!("Missing credential schema");
            (StatusCode::NOT_FOUND, "Missing credential schema").into_response()
        }
        Err(e) => {
            tracing::error!("Error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    post,
    path = "/ssi/openid4vci/final-1.0/{id}/nonce",
    params(
        ("id" = String, Path, description = "Issuance protocol id")
    ),
    responses(
        (status = 200, description = "OK", body = OpenID4VCINonceResponseRestDTO),
        (status = 500, description = "Server error"),
    ),
    tag = "openid4vci-final1_0",
    summary = "OID4VC - Generate nonce",
    description = indoc::formatdoc! {"
        This endpoint handles low-level mechanisms in interactions between agents.
        Deep understanding of the involved protocols is recommended.
    "},
)]
pub(crate) async fn oid4vci_final1_0_nonce(
    state: State<AppState>,
    WithRejection(Path(issuance_protocol_id), _): WithRejection<Path<String>, ErrorResponseRestDTO>,
) -> Response {
    let result = state
        .core
        .oid4vci_final1_0_service
        .generate_nonce(&issuance_protocol_id)
        .await;

    match result {
        Ok(value) => (
            StatusCode::OK,
            Json(OpenID4VCINonceResponseRestDTO::from(value)),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
