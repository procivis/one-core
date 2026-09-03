use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use axum_extra::extract::WithRejection;
use axum_extra::typed_header::TypedHeader;
use headers::authorization::Bearer;
use one_core::error::{ErrorCode, ErrorCodeMixin};
use one_core::service::oid4vci_final1_0::dto::{
    OID4VCIFinal1_0IssuerMetadataResponseEnum, OID4VCIFinal1_0IssuerMetadataResponseTypeEnum,
};
use one_core::service::oid4vci_final1_0::error::OID4VCIFinal1_0ServiceError;
use proc_macros::endpoint;
use shared_types::{CredentialId, CredentialSchemaId, IdentifierId};
use standardized_types::oauth2::authorization_server_metadata::AuthorizationServerMetadata;
use standardized_types::oauth2::token::TokenResponse;
use standardized_types::openid4vci::{
    CredentialOffer, CredentialRequest, NonceResponse, NotificationRequest,
};

use super::dto::{
    OpenID4VCIFinal1CredentialResponseRestDTO, OpenID4VCIIssuerMetadataResponseRestDTO,
    OpenID4VCITokenRequestRestDTO,
};
use crate::dto::error::ErrorResponseRestDTO;
use crate::endpoint::ssi::dto::{OpenID4VCIErrorResponseRestDTO, OpenID4VCIErrorRestEnum};
use crate::extractor::Accept;
use crate::headers::APPLICATION_JWT;
use crate::router::AppState;

#[endpoint(
    permissions = [],
    get,
    path = "/.well-known/openid-credential-issuer/ssi/openid4vci/final-1.0/{protocol_id}/{identifier_id}/{credential_schema_id}",
    params(
        ("protocol_id" = String, Path, description = "Issuance protocol id"),
        ("identifier_id" = IdentifierId, Path, description = "Identifier id"),
        ("credential_schema_id" = CredentialSchemaId, Path, description = "Credential schema id")
    ),
    responses(
        (status = 200, description = "OK", content(
            (OpenID4VCIIssuerMetadataResponseRestDTO = "application/json"),
            (String = "application/jwt")
        )),
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
    accept: TypedHeader<Accept>,
    state: State<AppState>,
    WithRejection(Path((protocol_id, identifier_id, credential_schema_id)), _): WithRejection<
        Path<(String, IdentifierId, CredentialSchemaId)>,
        ErrorResponseRestDTO,
    >,
) -> Response {
    let Some(response_type) = accept.negotiate(&[
        (
            &mime::APPLICATION_JSON,
            OID4VCIFinal1_0IssuerMetadataResponseTypeEnum::Model,
        ),
        (
            &APPLICATION_JWT,
            OID4VCIFinal1_0IssuerMetadataResponseTypeEnum::Jwt,
        ),
    ]) else {
        return StatusCode::NOT_ACCEPTABLE.into_response();
    };

    let result = state
        .core
        .oid4vci_final1_0_service
        .get_issuer_metadata(
            &protocol_id,
            &identifier_id,
            &credential_schema_id,
            response_type,
        )
        .await;

    match result {
        Ok(value) => {
            let response_body = match value {
                OID4VCIFinal1_0IssuerMetadataResponseEnum::Model(model) => {
                    Json(OpenID4VCIIssuerMetadataResponseRestDTO::from(*model)).into_response()
                }
                OID4VCIFinal1_0IssuerMetadataResponseEnum::Jwt(jwt) => {
                    ([(header::CONTENT_TYPE, APPLICATION_JWT.as_ref())], jwt).into_response()
                }
            };
            (StatusCode::OK, response_body).into_response()
        }
        Err(error) if matches!(error.error_code(), ErrorCode::BR_0006 | ErrorCode::BR_0089) => {
            tracing::error!("Not found error: {error}");
            StatusCode::NOT_FOUND.into_response()
        }
        Err(error) if matches!(error.error_code(), ErrorCode::BR_0418) => {
            tracing::error!("Invalid certificate type error: {error}");
            StatusCode::BAD_REQUEST.into_response()
        }
        Err(e) => {
            tracing::error!("Error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[endpoint(
    permissions = [],
    get,
    path = "/.well-known/oauth-authorization-server/ssi/openid4vci/final-1.0/{protocol_id}/{identifier_id}/{credential_schema_id}",
    params(
        ("protocol_id" = String, Path, description = "Issuance protocol id"),
        ("identifier_id" = IdentifierId, Path, description = "Identifier id"),
        ("credential_schema_id" = CredentialSchemaId, Path, description = "Credential schema id")
    ),
    responses(
        (status = 200, description = "OK", body = AuthorizationServerMetadata),
        (status = 404, description = "Credential schema not found"),
        (status = 500, description = "Server error"),
    ),
    tag = "openid4vci-final1_0",
    summary = "OID4VC - OAuth authorization server",
    description = indoc::formatdoc! {"
        This endpoint handles low-level mechanisms in interactions between agents.
        Deep understanding of the involved protocols is recommended.
    "},
)]
pub(crate) async fn oid4vci_final1_0_oauth_authorization_server(
    state: State<AppState>,
    WithRejection(Path((protocol_id, identifier_id, credential_schema_id)), _): WithRejection<
        Path<(String, IdentifierId, CredentialSchemaId)>,
        ErrorResponseRestDTO,
    >,
) -> Response {
    let result = state
        .core
        .oid4vci_final1_0_service
        .oauth_authorization_server(&protocol_id, &identifier_id, &credential_schema_id)
        .await;

    match result {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(error) if matches!(error.error_code(), ErrorCode::BR_0006 | ErrorCode::BR_0089) => {
            tracing::error!("Not found error: {error}");
            StatusCode::NOT_FOUND.into_response()
        }
        Err(e) => {
            tracing::error!("Error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[endpoint(
    permissions = [],
    get,
    path = "/ssi/openid4vci/final-1.0/{credential_schema_id}/offer/{credential_id}",
    params(
        ("credential_schema_id" = CredentialSchemaId, Path, description = "Credential schema id"),
        ("credential_id" = CredentialId, Path, description = "Credential id")
    ),
    responses(
        (status = 200, description = "OK", body = CredentialOffer),
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
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(OID4VCIFinal1_0ServiceError::OpenID4VCIError(error)) => {
            tracing::warn!("OpenID4VCI credential offer error: {:?}", error);
            (
                StatusCode::BAD_REQUEST,
                Json(OpenID4VCIErrorResponseRestDTO::from(error)),
            )
                .into_response()
        }
        Err(err) if matches!(err.error_code(), ErrorCode::BR_0001 | ErrorCode::BR_0442) => {
            tracing::warn!("Unsupported credential: {err}");
            StatusCode::NOT_FOUND.into_response()
        }
        Err(e) => {
            tracing::warn!("Error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[endpoint(
    permissions = [],
    post,
    path = "/ssi/openid4vci/final-1.0/{id}/token",
    request_body(content = OpenID4VCITokenRequestRestDTO, description = "Token request", content_type = "application/x-www-form-urlencoded"
    ),
    params(
        ("id" = CredentialSchemaId, Path, description = "Credential schema id"),
        ("OAuth-Client-Attestation" = inline(Option<String>), Header, description = "OAuth Client Attestation JWT for attestation-based client authentication", nullable = false),
        ("OAuth-Client-Attestation-PoP" = inline(Option<String>), Header, description = "OAuth Client Attestation Proof of Possession JWT", nullable = false)
    ),
    responses(
        (status = 200, description = "OK", body = TokenResponse),
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
    headers: HeaderMap,
    WithRejection(Form(request), _): WithRejection<
        Form<OpenID4VCITokenRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> Response {
    // https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-07.html#section-6.1
    let oauth_client_attestation = headers
        .get("OAuth-Client-Attestation")
        .and_then(|v| v.to_str().ok());

    let oauth_client_attestation_pop = headers
        .get("OAuth-Client-Attestation-PoP")
        .and_then(|v| v.to_str().ok());

    let result = async {
        state
            .core
            .oid4vci_final1_0_service
            .create_token(
                &id,
                request.try_into()?,
                oauth_client_attestation,
                oauth_client_attestation_pop,
            )
            .await
    }
    .await;

    match result {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(OID4VCIFinal1_0ServiceError::OpenID4VCIError(error)) => {
            tracing::error!("OpenID4VCI token validation error: {:?}", error);
            (
                StatusCode::BAD_REQUEST,
                Json(OpenID4VCIErrorResponseRestDTO::from(error)),
            )
                .into_response()
        }
        Err(e @ OID4VCIFinal1_0ServiceError::InvalidCredentialState(state)) => {
            tracing::error!("Invalid credential state state error: {state}");
            (
                StatusCode::BAD_REQUEST,
                Json(OpenID4VCIErrorResponseRestDTO {
                    error: OpenID4VCIErrorRestEnum::CredentialRequestDenied,
                    error_description: Some(format!(
                        "{} | Credential is in state: {}",
                        e.error_code(),
                        state
                    )),
                }),
            )
                .into_response()
        }
        Err(error) if matches!(error.error_code(), ErrorCode::BR_0006 | ErrorCode::BR_0089) => {
            tracing::error!("Not found error: {error}");
            StatusCode::NOT_FOUND.into_response()
        }
        Err(e) => {
            tracing::error!("Error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[endpoint(
    permissions = [],
    post,
    path = "/ssi/openid4vci/final-1.0/{id}/credential",
    request_body(content = CredentialRequest, description = "Credential request"),
    params(
        ("id" = CredentialSchemaId, Path, description = "Credential schema id")
    ),
    responses(
        (status = 200, description = "OK", body = OpenID4VCIFinal1CredentialResponseRestDTO),
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
    WithRejection(Json(request), _): WithRejection<Json<CredentialRequest>, ErrorResponseRestDTO>,
) -> Response {
    let access_token = token.token();
    let result = state
        .core
        .oid4vci_final1_0_service
        .create_credential(&credential_schema_id, access_token, request)
        .await;

    match result {
        Ok(value) => (
            StatusCode::OK,
            Json(OpenID4VCIFinal1CredentialResponseRestDTO::from(value)),
        )
            .into_response(),
        Err(OID4VCIFinal1_0ServiceError::OpenID4VCIError(error)) => {
            tracing::error!("OpenID4VCI credential validation error: {:?}", error);
            (
                StatusCode::BAD_REQUEST,
                Json(OpenID4VCIErrorResponseRestDTO::from(error)),
            )
                .into_response()
        }
        Err(e @ OID4VCIFinal1_0ServiceError::InvalidCredentialState(state)) => {
            tracing::error!("Invalid credential state error: {state}");
            (
                StatusCode::BAD_REQUEST,
                Json(OpenID4VCIErrorResponseRestDTO {
                    error: OpenID4VCIErrorRestEnum::CredentialRequestDenied,
                    error_description: Some(format!(
                        "{} | Credential is in state: {}",
                        e.error_code(),
                        state
                    )),
                }),
            )
                .into_response()
        }
        Err(error) if matches!(error.error_code(), ErrorCode::BR_0238) => (
            StatusCode::BAD_REQUEST,
            Json(OpenID4VCIErrorResponseRestDTO {
                error: OpenID4VCIErrorRestEnum::InvalidRequest,
                error_description: None,
            }),
        )
            .into_response(),
        Err(error) if matches!(error.error_code(), ErrorCode::BR_0483) => {
            tracing::warn!("Unsupported credential refresh: {error}");
            (
                StatusCode::BAD_REQUEST,
                Json(OpenID4VCIErrorResponseRestDTO {
                    error: OpenID4VCIErrorRestEnum::InvalidRequest,
                    error_description: Some(format!("{} | {error}", error.error_code())),
                }),
            )
                .into_response()
        }
        Err(error) if matches!(error.error_code(), ErrorCode::BR_0006 | ErrorCode::BR_0089) => {
            tracing::error!("Not found error: {error}");
            StatusCode::NOT_FOUND.into_response()
        }
        Err(e) => {
            tracing::error!("Error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[endpoint(
    permissions = [],
    post,
    path = "/ssi/openid4vci/final-1.0/{id}/notification",
    request_body(content = NotificationRequest, description = "Notification request"),
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
    WithRejection(Json(request), _): WithRejection<Json<NotificationRequest>, ErrorResponseRestDTO>,
) -> Response {
    let access_token = token.token();
    let result = state
        .core
        .oid4vci_final1_0_service
        .handle_notification(credential_schema_id, access_token, request)
        .await;

    match result {
        Ok(_) => (StatusCode::NO_CONTENT).into_response(),
        Err(OID4VCIFinal1_0ServiceError::OpenID4VCIError(error)) => {
            tracing::error!("OpenID4VCI credential notification error: {:?}", error);
            (
                StatusCode::BAD_REQUEST,
                Json(OpenID4VCIErrorResponseRestDTO::from(error)),
            )
                .into_response()
        }
        Err(error) if matches!(error.error_code(), ErrorCode::BR_0006 | ErrorCode::BR_0089) => {
            tracing::error!("Not found error: {error}");
            StatusCode::NOT_FOUND.into_response()
        }
        Err(e) => {
            tracing::error!("Error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[endpoint(
    permissions = [],
    post,
    path = "/ssi/openid4vci/final-1.0/{protocol_id}/nonce",
    params(
        ("protocol_id" = String, Path, description = "Issuance protocol id")
    ),
    responses(
        (status = 200, description = "OK", body = NonceResponse),
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
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(e) => {
            tracing::error!("Error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
