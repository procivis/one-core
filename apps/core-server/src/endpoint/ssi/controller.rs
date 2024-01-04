use super::dto::{
    ConnectRequestRestDTO, ConnectVerifierResponseRestDTO, IssuerResponseRestDTO,
    OpenID4VCIDiscoveryResponseRestDTO, OpenID4VPDirectPostRequestRestDTO,
    OpenID4VPDirectPostResponseRestDTO, PostSsiIssuerConnectQueryParams,
    PostSsiIssuerSubmitQueryParams, PostSsiVerifierConnectQueryParams, ProofRequestQueryParams,
};
use crate::dto::response::{EmptyOrErrorResponse, OkOrErrorResponse};
use crate::endpoint::ssi::dto::{
    DidWebResponseRestDTO, OpenID4VCICredentialRequestRestDTO, OpenID4VCICredentialResponseRestDTO,
    OpenID4VCIErrorResponseRestDTO, OpenID4VCIIssuerMetadataResponseRestDTO,
    OpenID4VCITokenRequestRestDTO, OpenID4VCITokenResponseRestDTO,
};
use crate::endpoint::{
    credential::dto::GetCredentialResponseRestDTO, ssi::dto::PostSsiIssuerRejectQueryParams,
};
use crate::router::AppState;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Form, Json,
};
use axum_extra::typed_header::TypedHeader;
use headers::authorization::Bearer;
use one_core::service::error::ServiceError;
use shared_types::DidId;
use uuid::Uuid;

#[utoipa::path(
    post,
    path = "/ssi/temporary-verifier/v1/connect",
    request_body = ConnectRequestRestDTO,
    responses(OkOrErrorResponse<ConnectVerifierResponseRestDTO>),
    params(
        PostSsiVerifierConnectQueryParams
    ),
    tag = "ssi",
)]
pub(crate) async fn ssi_verifier_connect(
    state: State<AppState>,
    Query(query): Query<PostSsiVerifierConnectQueryParams>,
    Json(request): Json<ConnectRequestRestDTO>,
) -> OkOrErrorResponse<ConnectVerifierResponseRestDTO> {
    let result = state
        .core
        .ssi_verifier_service
        .connect_to_holder(&query.proof, &request.did, &query.redirect_uri)
        .await;
    OkOrErrorResponse::from_result(result, state, "connecting verifier")
}

#[utoipa::path(
    get,
    path = "/ssi/did-web/v1/{id}/did.json",
    params(
        ("id" = Uuid, Path, description = "Did id")
    ),
    responses(OkOrErrorResponse<DidWebResponseRestDTO>),
    tag = "ssi",
)]
pub(crate) async fn get_did_web_document(
    state: State<AppState>,
    Path(id): Path<DidId>,
) -> OkOrErrorResponse<DidWebResponseRestDTO> {
    let result = state.core.did_service.get_did_web_document(&id).await;
    OkOrErrorResponse::from_result(result, state, "getting did:web document")
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
        Err(e) => {
            tracing::error!("Error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    post,
    path = "/ssi/oidc-verifier/v1/response",
    request_body(content = OpenID4VPDirectPostRequestRestDTO, description = "Verifier request", content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "OK", body = OpenID4VPDirectPostResponseRestDTO),
        (status = 400, description = "OIDC Verifier errors", body = OpenID4VCIErrorResponseRestDTO),
        (status = 409, description = "Wrong proof state"),
        (status = 500, description = "Server error"),
    ),
    tag = "ssi",
)]
pub(crate) async fn oidc_verifier_direct_post(
    state: State<AppState>,
    Form(request): Form<OpenID4VPDirectPostRequestRestDTO>,
) -> Response {
    let result = state
        .core
        .oidc_service
        .oidc_verifier_direct_post(request.into())
        .await;

    match result {
        Ok(value) => (
            StatusCode::OK,
            Json(OpenID4VPDirectPostResponseRestDTO::from(value)),
        )
            .into_response(),
        Err(ServiceError::OpenID4VCError(error)) => {
            tracing::error!("OpenID4VCI validation error: {:?}", error);
            (
                StatusCode::BAD_REQUEST,
                Json(OpenID4VCIErrorResponseRestDTO::from(error)),
            )
                .into_response()
        }
        Err(ServiceError::NotFound) => {
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
    post,
    path = "/ssi/temporary-verifier/v1/reject",
    responses(EmptyOrErrorResponse),
    params(ProofRequestQueryParams),
    tag = "ssi"
)]
pub(crate) async fn ssi_verifier_reject_proof(
    state: State<AppState>,
    Query(query): Query<ProofRequestQueryParams>,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .ssi_verifier_service
        .reject_proof(&query.proof)
        .await;
    EmptyOrErrorResponse::from_result(result, state, "rejecting proof")
}

#[utoipa::path(
    post,
    path = "/ssi/temporary-verifier/v1/submit",
    request_body = String, // signed JWT
    responses(EmptyOrErrorResponse),
    params(ProofRequestQueryParams),
    tag = "ssi",
)]
pub(crate) async fn ssi_verifier_submit_proof(
    state: State<AppState>,
    Query(query): Query<ProofRequestQueryParams>,
    request: String,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .ssi_verifier_service
        .submit_proof(&query.proof, &request)
        .await;
    EmptyOrErrorResponse::from_result(result, state, "submitting proof")
}

#[utoipa::path(
    post,
    path = "/ssi/temporary-issuer/v1/connect",
    request_body = ConnectRequestRestDTO,
    responses(OkOrErrorResponse<GetCredentialResponseRestDTO>),
    params(PostSsiIssuerConnectQueryParams),
    tag = "ssi",
)]
pub(crate) async fn ssi_issuer_connect(
    state: State<AppState>,
    Query(query): Query<PostSsiIssuerConnectQueryParams>,
    Json(request): Json<ConnectRequestRestDTO>,
) -> OkOrErrorResponse<GetCredentialResponseRestDTO> {
    let result = state
        .core
        .ssi_issuer_service
        .issuer_connect(&query.credential, &request.did)
        .await;
    OkOrErrorResponse::from_result(result, state, "connecting to issuer")
}

#[utoipa::path(
    post,
    path = "/ssi/temporary-issuer/v1/reject",
    responses(EmptyOrErrorResponse),
    params(PostSsiIssuerRejectQueryParams),
    tag = "ssi"
)]
pub(crate) async fn ssi_issuer_reject(
    state: State<AppState>,
    Query(query): Query<PostSsiIssuerRejectQueryParams>,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .ssi_issuer_service
        .issuer_reject(&query.credential_id)
        .await;
    EmptyOrErrorResponse::from_result(result, state, "rejecting proof")
}

#[utoipa::path(
    post,
    path = "/ssi/temporary-issuer/v1/submit",
    responses(OkOrErrorResponse<IssuerResponseRestDTO>),
    params(PostSsiIssuerSubmitQueryParams),
    tag = "ssi",
)]
pub(crate) async fn ssi_issuer_submit(
    state: State<AppState>,
    Query(query): Query<PostSsiIssuerSubmitQueryParams>,
) -> OkOrErrorResponse<IssuerResponseRestDTO> {
    let result = state
        .core
        .ssi_issuer_service
        .issuer_submit(&query.credential_id)
        .await;
    OkOrErrorResponse::from_result(result, state, "accepting credential")
}
