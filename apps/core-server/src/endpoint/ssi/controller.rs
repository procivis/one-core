use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use axum_extra::extract::WithRejection;
use axum_extra::typed_header::TypedHeader;
use headers::authorization::Bearer;
use headers::Authorization;
use one_core::provider::exchange_protocol::openid4vc::error::OpenID4VCError;
use one_core::provider::exchange_protocol::openid4vc::model::OpenID4VCITokenRequestDTO;
use one_core::service::error::{BusinessLogicError, EntityNotFoundError, ServiceError};
use one_core::service::revocation_list::dto::SupportedBitstringCredentialFormat;
use shared_types::{
    CredentialId, CredentialSchemaId, DidId, ProofId, ProofSchemaId, TrustAnchorId,
};
use uuid::Uuid;

use super::dto::{
    DidDocumentRestDTO, GetTrustAnchorResponseRestDTO, IssuerResponseRestDTO,
    JsonLDContextResponseRestDTO, OpenID4VCICredentialOfferRestDTO,
    OpenID4VCICredentialRequestRestDTO, OpenID4VCICredentialResponseRestDTO,
    OpenID4VCIDiscoveryResponseRestDTO, OpenID4VCIErrorResponseRestDTO, OpenID4VCIErrorRestEnum,
    OpenID4VCIIssuerMetadataResponseRestDTO, OpenID4VCITokenRequestRestDTO,
    OpenID4VCITokenResponseRestDTO, OpenID4VPClientMetadataResponseRestDTO,
    OpenID4VPDirectPostRequestRestDTO, OpenID4VPDirectPostResponseRestDTO,
    OpenID4VPPresentationDefinitionResponseRestDTO,
};
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::OkOrErrorResponse;
use crate::endpoint::credential_schema::dto::CredentialSchemaResponseRestDTO;
use crate::endpoint::proof_schema::dto::GetProofSchemaResponseRestDTO;
use crate::router::AppState;

#[utoipa::path(
    get,
    path = "/ssi/did-web/v1/{id}/did.json",
    params(
        ("id" = DidId, Path, description = "Did id")
    ),
    responses(OkOrErrorResponse<DidDocumentRestDTO>),
    tag = "ssi",
    summary = "Retrieve did:web document",
    description = indoc::formatdoc! {"
        This endpoint handles an aspect of the SSI interactions between agents and should **not** be used.
        For information on this endpoint, see directly the
        [did:web Method Specification](https://w3c-ccg.github.io/did-method-web/).
    "},
)]
pub(crate) async fn get_did_web_document(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<DidId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<DidDocumentRestDTO> {
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
        (status = 200, description = "OK", content(
            (String = "application/jwt", example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
            (String = "application/ld+json", example = json!({
                "@context": [
                  "https://www.w3.org/ns/credentials/v2"
                ],
                "id": "https://example.com/credentials/status/3",
                "type": ["VerifiableCredential", "BitstringStatusListCredential"],
                "issuer": "did:example:12345",
                "credentialSubject": {
                  "id": "https://example.com/status/3#list",
                  "type": "BitstringStatusList",
                  "statusPurpose": "revocation",
                  "encodedList": "uH4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA"
                }
              }))
        )),
        (status = 404, description = "Revocation list not found"),
        (status = 500, description = "Server error"),
    ),
    tag = "ssi",
    summary = "Revocation - retrieve list",
    description = indoc::formatdoc! {"
        This endpoint handles an aspect of the SSI interactions between agents and should **not** be used.
        See the [W3C Verifiable Credentials Status List 2021 specification](https://www.w3.org/TR/2023/WD-vc-status-list-20230427/).
    "},
)]
pub(crate) async fn get_revocation_list_by_id(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<Uuid>, ErrorResponseRestDTO>,
) -> Response {
    let result = state
        .core
        .revocation_list_service
        .get_revocation_list_by_id(&id)
        .await;

    match result {
        Ok(result) => {
            let content_type = match result.format {
                SupportedBitstringCredentialFormat::Jwt => "application/jwt".to_owned(),
                SupportedBitstringCredentialFormat::JsonLdClassic => {
                    "application/ld+json".to_owned()
                }
            };
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, content_type)],
                result.revocation_list,
            )
                .into_response()
        }
        Err(ServiceError::ConfigValidationError(error)) => {
            tracing::error!("Config validation error: {}", error);
            StatusCode::BAD_REQUEST.into_response()
        }
        Err(ServiceError::EntityNotFound(EntityNotFoundError::RevocationList(_))) => {
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
    path = "/ssi/revocation/v1/lvvc/{id}",
    params(
        ("id" = CredentialId, Path, description = "Credential id")
    ),
    responses(
        (status = 200, description = "OK", content_type = "text/plain"),
        (status = 400, description = "Credential in PENDING, REQUESTED or CREATED state/Invalid holder token"),
        (status = 404, description = "Credential not found"),
        (status = 500, description = "Server error"),
    ),
    tag = "ssi",
    summary = "Get LVVC by credential",
    description = "This endpoint handles an aspect of the SSI interactions between agents and should **not** be used.",
)]
pub(crate) async fn get_lvvc_by_credential_id(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<CredentialId>, ErrorResponseRestDTO>,
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
) -> Response {
    let result = state
        .core
        .revocation_list_service
        .get_lvvc_by_credential_id(&id, bearer.token())
        .await;

    match result {
        Ok(result) => (StatusCode::OK, Json(IssuerResponseRestDTO::from(result))).into_response(),
        Err(ServiceError::ConfigValidationError(error)) => {
            tracing::error!("Config validation error: {}", error);
            StatusCode::BAD_REQUEST.into_response()
        }
        Err(ServiceError::EntityNotFound(EntityNotFoundError::Credential(_))) => {
            tracing::error!("Missing credential");
            (StatusCode::NOT_FOUND, "Missing credential").into_response()
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
        ("id" = CredentialSchemaId, Path, description = "Credential schema id")
    ),
    responses(
        (status = 200, description = "OK", body = OpenID4VCIIssuerMetadataResponseRestDTO),
        (status = 404, description = "Credential schema not found"),
        (status = 500, description = "Server error"),
    ),
    tag = "ssi",
    summary = "OID4VC - Retrieve issuer metadata",
    description = indoc::formatdoc! {"
        This endpoint handles an aspect of the SSI interactions between agents and should **not** be used.
        For information on this endpoint, see directly the [OpenID for Verifiable Credentials
        specifications](https://openid.net/sg/openid4vc/specifications/).
    "},
)]
pub(crate) async fn oidc_get_issuer_metadata(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<CredentialSchemaId>, ErrorResponseRestDTO>,
) -> Response {
    let result = state.core.oidc_service.oidc_get_issuer_metadata(&id).await;

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
    path = "/ssi/oidc-issuer/v1/{id}/.well-known/openid-configuration",
    params(
        ("id" = CredentialSchemaId, Path, description = "Credential schema id")
    ),
    responses(
        (status = 200, description = "OK", body = OpenID4VCIDiscoveryResponseRestDTO),
        (status = 404, description = "Credential schema not found"),
        (status = 500, description = "Server error"),
    ),
    tag = "ssi",
    summary = "OID4VC - Service discovery",
    description = indoc::formatdoc! {"
        This endpoint handles an aspect of the SSI interactions between agents and should **not** be used.
        For information on this endpoint, see directly the [OpenID for Verifiable Credentials
        specifications](https://openid.net/sg/openid4vc/specifications/).
    "},
)]
pub(crate) async fn oidc_service_discovery(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<CredentialSchemaId>, ErrorResponseRestDTO>,
) -> Response {
    let result = state.core.oidc_service.oidc_service_discovery(&id).await;

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
    path = "/ssi/oidc-issuer/v1/{credential_schema_id}/offer/{credential_id}",
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
    tag = "ssi",
    summary = "OID4VC - Retrieve credential offer",
    description = indoc::formatdoc! {"
        This endpoint handles an aspect of the SSI interactions between agents and should **not** be used.
        For information on this endpoint, see directly the [OpenID for Verifiable Credentials
        specifications](https://openid.net/sg/openid4vc/specifications/).
    "},
)]
pub(crate) async fn oidc_get_credential_offer(
    state: State<AppState>,
    WithRejection(Path((credential_schema_id, credential_id)), _): WithRejection<
        Path<(CredentialSchemaId, CredentialId)>,
        ErrorResponseRestDTO,
    >,
) -> Response {
    let result = state
        .core
        .oidc_service
        .oidc_get_credential_offer(credential_schema_id, credential_id)
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
    path = "/ssi/oidc-issuer/v1/{id}/token",
    request_body(content = OpenID4VCITokenRequestRestDTO, description = "Token request", content_type = "application/x-www-form-urlencoded"),
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
    tag = "ssi",
    summary = "OID4VC - Create token",
    description = indoc::formatdoc! {"
        This endpoint handles an aspect of the SSI interactions between agents and should **not** be used.
        For information on this endpoint, see directly the [OpenID for Verifiable Credentials
        specifications](https://openid.net/sg/openid4vc/specifications/).
    "},
)]
pub(crate) async fn oidc_create_token(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<CredentialSchemaId>, ErrorResponseRestDTO>,
    WithRejection(Form(request), _): WithRejection<
        Form<OpenID4VCITokenRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> Response {
    let result = async {
        let request = OpenID4VCITokenRequestDTO::try_from(request)?;

        state
            .core
            .oidc_service
            .oidc_create_token(&id, request)
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
    path = "/ssi/oidc-issuer/v1/{id}/credential",
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
        ("OpenID4VCI" = [])
    ),
    tag = "ssi",
    summary = "OID4VC - Create credential",
    description = indoc::formatdoc! {"
        This endpoint handles an aspect of the SSI interactions between agents and should **not** be used.
        For information on this endpoint, see directly the [OpenID for Verifiable Credentials
        specifications](https://openid.net/sg/openid4vc/specifications/).
    "},
)]
pub(crate) async fn oidc_create_credential(
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
        .oidc_service
        .oidc_create_credential(&credential_schema_id, access_token, request.into())
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
    path = "/ssi/oidc-verifier/v1/response",
    request_body(content = OpenID4VPDirectPostRequestRestDTO, description = "Verifier request", content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "OK", body = OpenID4VPDirectPostResponseRestDTO),
        (status = 400, description = "OIDC Verifier errors", body = OpenID4VCIErrorResponseRestDTO),
        (status = 409, description = "Wrong proof state"),
        (status = 500, description = "Server error"),
    ),
    tag = "ssi",
    summary = "OID4VC - Verifier direct post",
    description = indoc::formatdoc! {"
        This endpoint handles an aspect of the SSI interactions between agents and should **not** be used.
        For information on this endpoint, see directly the [OpenID for Verifiable Credentials
        specifications](https://openid.net/sg/openid4vc/specifications/).
    "},
)]
pub(crate) async fn oidc_verifier_direct_post(
    state: State<AppState>,
    WithRejection(Form(request), _): WithRejection<
        Form<OpenID4VPDirectPostRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
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
        Err(
            ServiceError::OpenID4VCIError(error)
            | ServiceError::OpenID4VCError(OpenID4VCError::OpenID4VCI(error)),
        ) => {
            tracing::error!("OpenID4VCI validation error: {:?}", error);
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
    path = "/ssi/oidc-verifier/v1/{id}/presentation-definition",
    params(
        ("id" = ProofId, Path, description = "Proof id")
    ),
    responses(
        (status = 200, description = "OK", body = OpenID4VPPresentationDefinitionResponseRestDTO),
        (status = 400, description = "OIDC Verifier errors", body = OpenID4VCIErrorResponseRestDTO),
        (status = 404, description = "Proof does not exist"),
        (status = 500, description = "Server error"),
    ),
    tag = "ssi",
    summary = "OID4VC - Verifier presentation definition",
    description = indoc::formatdoc! {"
        This endpoint handles an aspect of the SSI interactions between agents and should **not** be used.
        For information on this endpoint, see directly the [OpenID for Verifiable Credentials
        specifications](https://openid.net/sg/openid4vc/specifications/).
    "},
)]
pub(crate) async fn oidc_verifier_presentation_definition(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<ProofId>, ErrorResponseRestDTO>,
) -> Response {
    let result = state
        .core
        .oidc_service
        .oidc_verifier_presentation_definition(id)
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
    path = "/ssi/oidc-verifier/v1/{id}/client-metadata",
    params(
        ("id" = ProofId, Path, description = "Proof id")
    ),
    responses(
        (status = 200, description = "OK", body = OpenID4VPClientMetadataResponseRestDTO),
        (status = 400, description = "OIDC Verifier errors", body = OpenID4VCIErrorResponseRestDTO),
        (status = 404, description = "Proof does not exist"),
        (status = 500, description = "Server error"),
    ),
    tag = "ssi",
    summary = "OID4VC - Client metadata",
    description = indoc::formatdoc! {"
        This endpoint handles an aspect of the SSI interactions between agents and should **not** be used.
        For information on this endpoint, see directly the [OpenID for Verifiable Credentials
        specifications](https://openid.net/sg/openid4vc/specifications/).
    "},
)]
pub(crate) async fn oidc_client_metadata(
    state: State<AppState>,
    WithRejection(Path(proof_id), _): WithRejection<Path<ProofId>, ErrorResponseRestDTO>,
) -> Response {
    let result = state
        .core
        .oidc_service
        .oidc_get_client_metadata(proof_id)
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
    path = "/ssi/context/v1/{id}",
    params(
        ("id" = String, Path, description = "context id or credentialSchemaId")
    ),
    responses(
        (status = 200, description = "OK", body = JsonLDContextResponseRestDTO, content_type = "application/ld+json"),
        (status = 404, description = "Credential schema not found"),
        (status = 500, description = "Server error"),
    ),
    tag = "ssi",
    summary = "Retrieve @context",
    description = indoc::formatdoc! {"
        This endpoint handles an aspect of the SSI interactions between agents and should **not** be used.
        For information on this endpoint, see directly the
        [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/).
    "},
)]
pub(crate) async fn get_json_ld_context(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<String>, ErrorResponseRestDTO>,
) -> Response {
    let result = state.core.ssi_issuer_service.get_json_ld_context(&id).await;

    match result {
        Ok(value) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/ld+json")],
            Json(JsonLDContextResponseRestDTO::from(value)),
        )
            .into_response(),
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
    path = "/ssi/trust/v1/{trustAnchorId}",
    params(
        ("trustAnchorId" = TrustAnchorId, Path, description = "Trust anchor id")
    ),
    responses(
        (status = 200, description = "OK", body = GetTrustAnchorResponseRestDTO),
        (status = 400, description = "Trust anchor type is not SIMPLE_TRUST_LIST"),
        (status = 404, description = "Trust anchor not found"),
        (status = 500, description = "Server error"),
    ),
    tag = "ssi",
    summary = "Retrieve Trust List",
    description = "This endpoint handles an aspect of the SSI interactions between agents and should **not** be used.",
)]
pub(crate) async fn ssi_get_trust_list(
    state: State<AppState>,
    WithRejection(Path(trust_anchor_id), _): WithRejection<
        Path<TrustAnchorId>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<GetTrustAnchorResponseRestDTO> {
    let result = state
        .core
        .trust_anchor_service
        .get_trust_list(trust_anchor_id)
        .await;

    OkOrErrorResponse::from_result(result, state, "getting trust list")
}

#[utoipa::path(
    get,
    path = "/ssi/schema/v1/{id}",
    params(
        ("id" = CredentialSchemaId, Path, description = "Credential schema id")
    ),
    responses(
        (status = 200, description = "OK", body = CredentialSchemaResponseRestDTO),
        (status = 404, description = "Credential schema not found"),
        (status = 500, description = "Server error"),
    ),
    tag = "ssi",
    summary = "Retrieve credential schema service",
    description = "This endpoint handles an aspect of the SSI interactions between agents and should **not** be used.",
)]
pub(crate) async fn ssi_get_credential_schema(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<CredentialSchemaId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<CredentialSchemaResponseRestDTO> {
    let result = state
        .core
        .credential_schema_service
        .get_credential_schema(&id)
        .await;

    OkOrErrorResponse::from_result(result, state, "getting credential schema")
}

#[utoipa::path(
    get,
    path = "/ssi/proof-schema/v1/{id}",
    params(
        ("id" = ProofSchemaId, Path, description = "Proof schema id")
    ),
    responses(
        (status = 200, description = "OK", body = GetProofSchemaResponseRestDTO),
        (status = 404, description = "Proof schema not found"),
        (status = 500, description = "Server error"),
    ),
    tag = "ssi",
    summary = "Retrieve proof schema service",
    description = "This endpoint handles an aspect of the SSI interactions between agents and should **not** be used.",
)]
pub(crate) async fn ssi_get_proof_schema(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<ProofSchemaId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetProofSchemaResponseRestDTO> {
    let result = state.core.proof_schema_service.get_proof_schema(&id).await;
    OkOrErrorResponse::from_result(result, state, "getting proof schema")
}
