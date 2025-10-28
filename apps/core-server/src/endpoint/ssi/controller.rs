use axum::Json;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum_extra::extract::WithRejection;
use axum_extra::typed_header::TypedHeader;
use headers::Authorization;
use headers::authorization::Bearer;
use one_core::service::error::{BusinessLogicError, EntityNotFoundError, ServiceError};
use shared_types::{
    CredentialId, CredentialSchemaId, DidId, DidValue, OrganisationId, ProofSchemaId, TrustAnchorId,
};
use uuid::Uuid;

use super::dto::{
    DidDocumentRestDTO, GetTrustAnchorResponseRestDTO, JsonLDContextResponseRestDTO,
    LVVCIssuerResponseRestDTO, PatchTrustEntityRequestRestDTO, SSIPostTrustEntityRequestRestDTO,
    SdJwtVcTypeMetadataResponseRestDTO,
};
use crate::dto::common::EntityResponseRestDTO;
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{CreatedOrErrorResponse, EmptyOrErrorResponse, OkOrErrorResponse};
use crate::endpoint::credential_schema::dto::CredentialSchemaResponseRestDTO;
use crate::endpoint::proof_schema::dto::GetProofSchemaResponseRestDTO;
use crate::endpoint::trust_entity::dto::GetTrustEntityResponseRestDTO;
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
        Retrieve a `did:web` document by its UUID.
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
    path = "/ssi/did-webvh/v1/{id}/did.jsonl",
    params(
        ("id" = DidId, Path, description = "Did id")
    ),
    responses(
        (status = 200, description = "success response", content_type = "text/jsonl"),
        (status = 400, description = "invalid did method"),
        (status = 404, description = "did not found"),
        (status = 500, description = "internal server error"),
    ),
    tag = "ssi",
    summary = "Retrieve did:webvh(did:tdw) document",
    description = indoc::formatdoc! {"
        Retrieve a `did:webvh` (or `did:tdw`) document by its UUID.
    "},
)]
pub(crate) async fn get_did_webvh_log(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<DidId>, ErrorResponseRestDTO>,
) -> Response {
    let result = state.core.did_service.get_did_webvh_log(&id).await;

    match result {
        Ok(log) => (StatusCode::OK, [(header::CONTENT_TYPE, "text/jsonl")], log).into_response(),
        Err(ServiceError::EntityNotFound(_)) => {
            tracing::error!("did:webvh not found");
            (StatusCode::NOT_FOUND, "Did not found").into_response()
        }
        Err(ServiceError::BusinessLogic(BusinessLogicError::InvalidDidMethod { method })) => {
            tracing::error!("Expected did:webvh found {method}");
            (StatusCode::BAD_REQUEST, "Invalid did method").into_response()
        }
        Err(e) => {
            tracing::error!("Error getting did:webvh: {e}");
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
        Retrieve a revocation list by its UUID.
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
        Ok(result) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, result.get_content_type())],
            result.revocation_list,
        )
            .into_response(),
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
        (status = 200, description = "OK", body = LVVCIssuerResponseRestDTO),
        (status = 400, description = "Credential in PENDING, REQUESTED or CREATED state/Invalid holder token"),
        (status = 404, description = "Credential not found"),
        (status = 500, description = "Server error"),
    ),
    security(
        ("remote-agent" = [])
    ),
    tag = "ssi",
    summary = "Get LVVC by credential",
    description = indoc::formatdoc! {"
        Retrieve the LVVC of a credential by the credential's UUID. This is needed to
        check the validity of credential's issued with the LVVC revocation method.
    "},
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
        Ok(result) => (
            StatusCode::OK,
            Json(LVVCIssuerResponseRestDTO::from(result)),
        )
            .into_response(),
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
        Retrieve the `@context` of a JSON-LD credential by the UUID of the
        credential schema.
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
        Err(ServiceError::ValidationError(e)) => {
            tracing::error!("Validation error: {e}");
            StatusCode::BAD_REQUEST.into_response()
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
    description = indoc::formatdoc! {"
        Retrieve a trust list by the UUID of the trust anchor.
    "},
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
    path = "/ssi/trust-entity/v1/{didValue}",
    params(
        ("didValue" = DidValue, Path, description = "DID value")
    ),
    responses(OkOrErrorResponse<GetTrustEntityResponseRestDTO>),
    security(
        ("remote-agent" = [])
    ),
    tag = "ssi",
    summary = "Retrieve a trust entity",
    description = indoc::formatdoc! {"
        Retrieve a trust entity by the value of the DID.
    "},
)]
pub(crate) async fn ssi_get_trust_entity(
    state: State<AppState>,
    WithRejection(Path(did_value), _): WithRejection<Path<DidValue>, ErrorResponseRestDTO>,
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
) -> OkOrErrorResponse<GetTrustEntityResponseRestDTO> {
    let result = state
        .core
        .trust_entity_service
        .publisher_get_trust_entity_for_did(did_value, bearer.token())
        .await;

    OkOrErrorResponse::from_result(result, state, "getting trust entity")
}

#[utoipa::path(
    patch,
    path = "/ssi/trust-entity/v1/{didValue}",
    params(
        ("didValue" = DidValue, Path, description = "DID value")
    ),
    request_body = PatchTrustEntityRequestRestDTO,
    responses(EmptyOrErrorResponse),
    security(
        ("remote-agent" = [])
    ),
    tag = "ssi",
    summary = "Update a trust entity",
    description = indoc::formatdoc! {"
        Update a trust entity by its DID value.
    "},
)]
pub(crate) async fn ssi_patch_trust_entity(
    state: State<AppState>,
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
    WithRejection(Path(did_value), _): WithRejection<Path<DidValue>, ErrorResponseRestDTO>,
    WithRejection(Json(request), _): WithRejection<
        Json<PatchTrustEntityRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> EmptyOrErrorResponse {
    let request = match request.try_into() {
        Ok(request) => request,
        Err(err) => {
            return EmptyOrErrorResponse::from_service_error(
                err,
                state.config.hide_error_response_cause,
            );
        }
    };
    let result = state
        .core
        .trust_entity_service
        .update_trust_entity_by_did(did_value, request, bearer.token())
        .await;

    EmptyOrErrorResponse::from_result(result, state, "getting trust entity")
}

#[utoipa::path(
    post,
    path = "/ssi/trust-entity/v1",
    request_body = SSIPostTrustEntityRequestRestDTO,
    responses(CreatedOrErrorResponse<EntityResponseRestDTO>),
    security(
        ("remote-agent" = [])
    ),
    tag = "ssi",
    summary = "Create a trust entity",
    description = indoc::formatdoc! {"
        Add a trust entity to a trust anchor.
    "},
)]
pub(crate) async fn ssi_post_trust_entity(
    state: State<AppState>,
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
    WithRejection(Json(request), _): WithRejection<
        Json<SSIPostTrustEntityRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<EntityResponseRestDTO> {
    let request = match request.try_into() {
        Ok(request) => request,
        Err(err) => {
            return CreatedOrErrorResponse::from_service_error(
                err,
                state.config.hide_error_response_cause,
            );
        }
    };
    let result = state
        .core
        .trust_entity_service
        .publisher_create_trust_entity_for_did(request, bearer.token())
        .await;

    CreatedOrErrorResponse::from_result(result, state, "getting trust entity")
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
    description = indoc::formatdoc! {"
        Retrieve a credential schema by its UUID.
    "},
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
    description = indoc::formatdoc! {"
        Retrieve a proof schema by its UUID.
    "},
)]
pub(crate) async fn ssi_get_proof_schema(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<ProofSchemaId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetProofSchemaResponseRestDTO> {
    let result = state.core.proof_schema_service.get_proof_schema(&id).await;
    OkOrErrorResponse::from_result(result, state, "getting proof schema")
}

#[utoipa::path(
    get,
    path = "/ssi/vct/v1/{organisationId}/{vctType}",
    params(
        ("organisationId" = OrganisationId, Path, description = "Organization id"),
        ("vctType" = String, Path, description = "VctType")
    ),
    responses(
        (status = 200, description = "OK", body = SdJwtVcTypeMetadataResponseRestDTO),
        (status = 404, description = "Type metadata not found"),
        (status = 500, description = "Server error"),
    ),
    tag = "ssi",
    summary = "Retrieve SD-JWT VC type metadata service",
    description = indoc::formatdoc! {"
        Retrieve the type metadata of an SD-JWT VC credential.
    "},
)]
pub(crate) async fn ssi_get_sd_jwt_vc_type_metadata(
    state: State<AppState>,
    WithRejection(Path((organisation_id, vct_type)), _): WithRejection<
        Path<(OrganisationId, String)>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<SdJwtVcTypeMetadataResponseRestDTO> {
    let result = state
        .core
        .ssi_issuer_service
        .get_vct_metadata(organisation_id, vct_type)
        .await;
    OkOrErrorResponse::from_result(result, state, "getting SD-JWT VC type metadata")
}
