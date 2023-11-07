use super::dto::{
    ConnectIssuerResponseRestDTO, ConnectRequestRestDTO, ConnectVerifierResponseRestDTO,
    OpenID4VCIDiscoveryResponseRestDTO, PostSsiIssuerConnectQueryParams,
    PostSsiIssuerSubmitQueryParams, PostSsiVerifierConnectQueryParams, ProofRequestQueryParams,
};
use crate::endpoint::ssi::dto::{
    OpenID4VCICredentialRequestRestDTO, OpenID4VCICredentialResponseRestDTO,
    OpenID4VCIErrorResponseRestDTO, OpenID4VCIIssuerMetadataResponseRestDTO,
    OpenID4VCITokenRequestRestDTO, OpenID4VCITokenResponseRestDTO,
};
use crate::endpoint::{
    credential::dto::GetCredentialResponseRestDTO, ssi::dto::PostSsiIssuerRejectQueryParams,
};
use crate::router::AppState;
use axum::{
    extract::{Path, Query, State},
    headers::{self, authorization::Bearer},
    http::StatusCode,
    response::{IntoResponse, Response},
    Form, Json, TypedHeader,
};
use one_core::service::error::ServiceError;
use uuid::Uuid;

#[utoipa::path(
    post,
    path = "/ssi/temporary-verifier/v1/connect",
    request_body = ConnectRequestRestDTO,
    responses(
        (status = 200, description = "OK", body = ConnectVerifierResponseRestDTO),
        (status = 400, description = "Invalid request"),
        (status = 404, description = "Proof not found"),
        (status = 409, description = "Invalid proof state"),
        (status = 500, description = "Server error"),
    ),
    params(
        PostSsiVerifierConnectQueryParams
    ),
    tag = "ssi",
)]
pub(crate) async fn ssi_verifier_connect(
    state: State<AppState>,
    Query(query): Query<PostSsiVerifierConnectQueryParams>,
    Json(request): Json<ConnectRequestRestDTO>,
) -> Response {
    let result = state
        .core
        .ssi_verifier_service
        .connect_to_holder(&query.proof, &request.did)
        .await;

    match result {
        Ok(result) => (
            StatusCode::OK,
            Json(ConnectVerifierResponseRestDTO::from(result)),
        )
            .into_response(),
        Err(ServiceError::AlreadyExists) => {
            tracing::warn!("Already finished");
            (StatusCode::CONFLICT, "Already finished").into_response()
        }
        Err(ServiceError::IncorrectParameters) => {
            tracing::warn!("Wrong parameters");
            (StatusCode::BAD_REQUEST, "Wrong parameters").into_response()
        }
        Err(ServiceError::NotFound) => {
            tracing::error!("Missing proof");
            (StatusCode::NOT_FOUND, "Missing proof").into_response()
        }
        Err(e) => {
            tracing::error!("Error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    get,
    path = "/ssi/revocation/v1/list/{id}",
    params(
        ("id" = Uuid, Path, description = "Revocation list id")
    ),
    responses(
        (status = 200, description = "OK", content_type = "text/plain"),
        (status = 404, description = "Revocation list not found"),
        (status = 500, description = "Server error"),
    ),
    tag = "ssi",
)]
pub(crate) async fn get_revocation_list_by_id(
    state: State<AppState>,
    Path(id): Path<Uuid>,
) -> Response {
    let result = state
        .core
        .revocation_list_service
        .get_revocation_list_by_id(&id)
        .await;

    match result {
        Ok(result) => (StatusCode::OK, result).into_response(),
        Err(ServiceError::NotFound) => {
            tracing::error!("Missing revocation list");
            (StatusCode::NOT_FOUND, "Missing revocation list").into_response()
        }
        Err(e) => {
            tracing::error!("Error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    get,
    path = "/ssi/oidc-issuer/v1/{id}/.well-known/openid-credential-issuer",
    params(
        ("id" = Uuid, Path, description = "Credential schema id")
    ),
    responses(
        (status = 200, description = "OK", body = OpenID4VCIIssuerMetadataResponseRestDTO),
        (status = 404, description = "Credential schema not found"),
        (status = 500, description = "Server error"),
    ),
    tag = "ssi",
)]
pub(crate) async fn oidc_get_issuer_metadata(
    state: State<AppState>,
    Path(id): Path<Uuid>,
) -> Response {
    let result = state.core.oidc_service.oidc_get_issuer_metadata(&id).await;

    match result {
        Ok(value) => (
            StatusCode::OK,
            Json(OpenID4VCIIssuerMetadataResponseRestDTO::from(value)),
        )
            .into_response(),
        Err(ServiceError::NotFound) => {
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
    path = "/ssi/oidc-issuer/v1/{id}/.well-known/openid-configuration",
    params(
        ("id" = Uuid, Path, description = "Credential schema id")
    ),
    responses(
        (status = 200, description = "OK", body = OpenID4VCIDiscoveryResponseRestDTO),
        (status = 404, description = "Credential schema not found"),
        (status = 500, description = "Server error"),
    ),
    tag = "ssi",
)]
pub(crate) async fn oidc_service_discovery(
    state: State<AppState>,
    Path(id): Path<Uuid>,
) -> Response {
    let result = state.core.oidc_service.oidc_service_discovery(&id).await;

    match result {
        Ok(value) => (
            StatusCode::OK,
            Json(OpenID4VCIDiscoveryResponseRestDTO::from(value)),
        )
            .into_response(),
        Err(ServiceError::NotFound) => {
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
    path = "/ssi/oidc-issuer/v1/{id}/token",
    request_body(content = OpenID4VCITokenRequestRestDTO, description = "Token request", content_type = "application/x-www-form-urlencoded"),
    params(
        ("id" = Uuid, Path, description = "Credential schema id")
    ),
    responses(
        (status = 200, description = "OK", body = OpenID4VCITokenResponseRestDTO),
        (status = 400, description = "OIDC token errors", body = OpenID4VCIErrorResponseRestDTO),
        (status = 404, description = "Credential schema not found"),
        (status = 409, description = "Wrong credential state"),
        (status = 500, description = "Server error"),
    ),
    tag = "ssi",
)]
pub(crate) async fn oidc_create_token(
    state: State<AppState>,
    Path(id): Path<Uuid>,
    Form(request): Form<OpenID4VCITokenRequestRestDTO>,
) -> Response {
    let result = state
        .core
        .oidc_service
        .oidc_create_token(&id, request.into())
        .await;

    match result {
        Ok(value) => (
            StatusCode::OK,
            Json(OpenID4VCITokenResponseRestDTO::from(value)),
        )
            .into_response(),
        Err(ServiceError::OpenID4VCError(error)) => {
            tracing::error!("OpenID4VCI token validation error: {:?}", error);
            (
                StatusCode::BAD_REQUEST,
                Json(OpenID4VCIErrorResponseRestDTO::from(error)),
            )
                .into_response()
        }
        Err(ServiceError::NotFound) => {
            tracing::error!("Missing credential schema");
            (StatusCode::NOT_FOUND, "Missing credential schema").into_response()
        }
        Err(ServiceError::AlreadyExists) => {
            tracing::warn!("Already finished");
            (StatusCode::CONFLICT, "Wrong credential state").into_response()
        }
        Err(e) => {
            tracing::error!("Error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    post,
    path = "/ssi/oidc-issuer/v1/{id}/credential",
    request_body(content = OpenID4VCICredentialRequestRestDTO, description = "Credential request"),
    params(
        ("id" = Uuid, Path, description = "Credential schema id")
    ),
    responses(
        (status = 200, description = "OK", body = OpenID4VCICredentialResponseRestDTO),
        (status = 400, description = "OIDC credential errors", body = OpenID4VCIErrorResponseRestDTO),
        (status = 404, description = "Credential schema not found"),
        (status = 409, description = "Wrong credential state"),
        (status = 500, description = "Server error"),
    ),
    security(
        ("OpenID4VCI" = [])
    ),
    tag = "ssi",
)]
pub(crate) async fn oidc_create_credential(
    state: State<AppState>,
    Path(credential_schema_id): Path<Uuid>,
    TypedHeader(token): TypedHeader<headers::Authorization<Bearer>>,
    Json(request): Json<OpenID4VCICredentialRequestRestDTO>,
) -> Response {
    let access_token = token.token();
    let result = state
        .core
        .oidc_service
        .oidc_create_credential(&credential_schema_id, access_token, request.into())
        .await;

    match result {
        Ok(value) => (
            StatusCode::OK,
            Json(OpenID4VCICredentialResponseRestDTO::from(value)),
        )
            .into_response(),
        Err(ServiceError::OpenID4VCError(error)) => {
            tracing::error!("OpenID4VCI credential validation error: {:?}", error);
            (
                StatusCode::BAD_REQUEST,
                Json(OpenID4VCIErrorResponseRestDTO::from(error)),
            )
                .into_response()
        }
        Err(ServiceError::NotFound) => {
            tracing::error!("Missing credential schema");
            (StatusCode::NOT_FOUND, "Missing credential schema").into_response()
        }
        Err(ServiceError::AlreadyExists) => {
            tracing::warn!("Already finished");
            (StatusCode::CONFLICT, "Wrong credential state").into_response()
        }
        Err(e) => {
            tracing::error!("Error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    post,
    path = "/ssi/temporary-verifier/v1/reject",
    responses(
        (status = 204, description = "No content"),
        (status = 400, description = "Wrong proof request state"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Not found"),
    ),
    params(
        ProofRequestQueryParams
    ),
    tag = "ssi",
)]
pub(crate) async fn ssi_verifier_reject_proof(
    state: State<AppState>,
    Query(query): Query<ProofRequestQueryParams>,
) -> Response {
    let result = state
        .core
        .ssi_verifier_service
        .reject_proof(&query.proof)
        .await;

    match result {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => match error {
            ServiceError::NotUpdated => StatusCode::BAD_REQUEST.into_response(),
            ServiceError::NotFound => StatusCode::NOT_FOUND.into_response(),
            _ => {
                tracing::error!("Error while rejecting proof");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        },
    }
}

#[utoipa::path(
    post,
    path = "/ssi/temporary-verifier/v1/submit",
    request_body = String, // signed JWT
    responses(
        (status = 204, description = "OK"),
        (status = 400, description = "Invalid request"),
        (status = 404, description = "Proof not found"),
        (status = 409, description = "Invalid proof state"),
        (status = 500, description = "Server error"),
    ),
    params(
        ProofRequestQueryParams
    ),
    tag = "ssi",
)]
pub(crate) async fn ssi_verifier_submit_proof(
    state: State<AppState>,
    Query(query): Query<ProofRequestQueryParams>,
    request: String,
) -> Response {
    let result = state
        .core
        .ssi_verifier_service
        .submit_proof(&query.proof, &request)
        .await;

    match result {
        Ok(_) => (StatusCode::NO_CONTENT).into_response(),
        Err(ServiceError::AlreadyExists) => {
            tracing::warn!("Already finished");
            (StatusCode::CONFLICT, "Already finished").into_response()
        }
        Err(ServiceError::NotFound) => {
            tracing::error!("Missing proof");
            (StatusCode::NOT_FOUND, "Missing proof").into_response()
        }
        Err(ServiceError::IncorrectParameters) => {
            tracing::error!("Wrong arguments");
            (StatusCode::BAD_REQUEST, "Wrong arguments").into_response()
        }
        Err(e) => {
            tracing::error!("Error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    post,
    path = "/ssi/temporary-issuer/v1/connect",
    request_body = ConnectRequestRestDTO,
    responses(
        (status = 200, description = "OK", body = GetCredentialResponseRestDTO),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Credential not found"),
        (status = 500, description = "Server error"),
    ),
    params(
        PostSsiIssuerConnectQueryParams
    ),
    tag = "ssi",
)]
pub(crate) async fn ssi_issuer_connect(
    state: State<AppState>,
    Query(query): Query<PostSsiIssuerConnectQueryParams>,
    Json(request): Json<ConnectRequestRestDTO>,
) -> Response {
    let result = state
        .core
        .ssi_issuer_service
        .issuer_connect(&query.credential, &request.did)
        .await;

    match result {
        Ok(value) => (
            StatusCode::OK,
            Json(GetCredentialResponseRestDTO::from(value)),
        )
            .into_response(),
        Err(ServiceError::AlreadyExists) => {
            tracing::error!("Already issued");
            (StatusCode::CONFLICT, "Already issued").into_response()
        }
        Err(ServiceError::NotFound) => {
            tracing::error!("Missing credential");
            (StatusCode::NOT_FOUND, "Missing credential").into_response()
        }
        Err(ServiceError::IncorrectParameters) => {
            tracing::error!("Invalid arguments");
            (StatusCode::BAD_REQUEST, "Invalid arguments").into_response()
        }
        Err(e) => {
            tracing::error!("Error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    post,
    path = "/ssi/temporary-issuer/v1/reject",
    responses(
        (status = 200, description = "OK"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Server error"),
    ),
    params(
        PostSsiIssuerRejectQueryParams
    ),
    tag = "ssi",
)]
pub(crate) async fn ssi_issuer_reject(
    state: State<AppState>,
    Query(query): Query<PostSsiIssuerRejectQueryParams>,
) -> Response {
    let result = state
        .core
        .ssi_issuer_service
        .issuer_reject(&query.credential_id)
        .await;

    match result {
        Ok(_) => (StatusCode::OK.into_response()).into_response(),
        Err(ServiceError::NotFound) => {
            tracing::error!("Missing credential");
            (StatusCode::NOT_FOUND, "Missing credential").into_response()
        }
        Err(ServiceError::AlreadyExists) => {
            tracing::error!("Invalid state");
            (StatusCode::BAD_REQUEST, "Invalid state").into_response()
        }
        Err(e) => {
            tracing::error!("Error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    post,
    path = "/ssi/temporary-issuer/v1/submit",
    responses(
        (status = 200, description = "OK", body = ConnectIssuerResponseRestDTO),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Not found"),
        (status = 409, description = "Already issued"),
        (status = 500, description = "Server error"),
    ),
    params(
        PostSsiIssuerSubmitQueryParams
    ),
    tag = "ssi",
)]
pub(crate) async fn ssi_issuer_submit(
    state: State<AppState>,
    Query(query): Query<PostSsiIssuerSubmitQueryParams>,
) -> Response {
    let result = state
        .core
        .ssi_issuer_service
        .issuer_submit(&query.credential_id)
        .await;

    match result {
        Ok(result) => (
            StatusCode::OK,
            Json(ConnectIssuerResponseRestDTO::from(result)),
        )
            .into_response(),
        Err(ServiceError::AlreadyExists) => {
            tracing::error!("Already issued");
            (StatusCode::CONFLICT, "Already issued").into_response()
        }
        Err(ServiceError::NotFound) => {
            tracing::error!("Missing credential");
            (StatusCode::NOT_FOUND, "Missing credential").into_response()
        }
        Err(ServiceError::IncorrectParameters) => {
            tracing::error!("Invalid arguments");
            (StatusCode::BAD_REQUEST, "Invalid arguments").into_response()
        }
        Err(e) => {
            tracing::error!("Error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
