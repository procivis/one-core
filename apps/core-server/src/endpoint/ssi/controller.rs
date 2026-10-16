use axum::Json;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum_extra::extract::WithRejection;
use axum_extra::typed_header::TypedHeader;
use one_core::error::{ErrorCode, ErrorCodeMixin};
use one_core::service::certificate::dto::CertificateFormatEnum;
use one_core::service::did::error::DidServiceError;
use one_core::service::ssi_issuer::error::IssuerServiceError;
use one_core::service::trust_list_publication::dto::TrustListContentTypeDTO;
use one_core::service::trust_list_publication::error::TrustListPublicationServiceError;
use proc_macros::endpoint;
use shared_types::{
    CertificateId, CredentialFormat, CredentialSchemaId, DidId, OrganisationId, ProofSchemaId,
    RevocationListId, TrustCollectionId, TrustListPublicationId,
};

use super::dto::{
    DidDocumentRestDTO, JsonLDContextResponseRestDTO, SdJwtVcTypeMetadataResponseRestDTO,
};
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::OkOrErrorResponse;
use crate::endpoint::credential_schema::dto::{
    CredentialSchemaResponseRestDTO, CredentialSchemaV2ResponseRestDTO,
};
use crate::endpoint::proof_schema::dto::GetProofSchemaResponseRestDTO;
use crate::endpoint::ssi::dto::TrustCollectionResponseRestDTO;
use crate::extractor::Accept;
use crate::headers::{
    APPLICATION_COSE_X509, APPLICATION_JSONL_JSON, APPLICATION_JWT, APPLICATION_PEM_CHAIN,
    APPLICATION_XML, TEXT_JSONL,
};
use crate::router::AppState;
#[endpoint(
    permissions = [],
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

#[endpoint(
    permissions = [],
    get,
    path = "/ssi/did-webvh/v1/{id}/did.jsonl",
    params(
        ("id" = DidId, Path, description = "Did id")
    ),
    responses(
        (status = 200, description = "success response", content(
            (String = "text/jsonl"),
            (String = "application/jsonl+json")
        )),
        (status = 400, description = "invalid did method"),
        (status = 404, description = "did not found"),
        (status = 500, description = "internal server error"),
    ),
    tag = "ssi",
    summary = "Retrieve did:webvh(did:tdw) document",
    description = indoc::formatdoc! {"
        Retrieve a `did:webvh` (or `did:tdw`) document by its UUID.

        The log is served as `text/jsonl` unless the Accept header prefers
        `application/jsonl+json`.
    "},
)]
pub(crate) async fn get_did_webvh_log(
    accept: Option<TypedHeader<Accept>>,
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<DidId>, ErrorResponseRestDTO>,
) -> Response {
    // both media types are served; the spec-mandated one wins unless the client
    // explicitly prefers the other
    let content_type = accept
        .map(|TypedHeader(accept)| accept)
        .unwrap_or_default()
        .negotiate(&[
            (&TEXT_JSONL, TEXT_JSONL.as_ref()),
            (&APPLICATION_JSONL_JSON, APPLICATION_JSONL_JSON.as_ref()),
        ])
        .unwrap_or_else(|| TEXT_JSONL.as_ref());

    let result = state.core.did_service.get_did_webvh_log(&id).await;

    match result {
        Ok(log) => (StatusCode::OK, [(header::CONTENT_TYPE, content_type)], log).into_response(),
        Err(DidServiceError::NotFound(_)) => {
            tracing::error!("did:webvh not found");
            (StatusCode::NOT_FOUND, "Did not found").into_response()
        }
        Err(DidServiceError::InvalidMethod { method }) => {
            tracing::error!("Expected did:webvh found {method}");
            (StatusCode::BAD_REQUEST, "Invalid did method").into_response()
        }
        Err(e) => {
            tracing::error!("Error getting did:webvh: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[endpoint(
    permissions = [],
    get,
    path = "/ssi/revocation/v1/list/{id}",
    params(
        ("id" = RevocationListId, Path, description = "Revocation list id")
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
              })),
            (String = "application/statuslist+jwt"),
            ([u8] = "application/statuslist+cwt")
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
    WithRejection(Path(id), _): WithRejection<Path<RevocationListId>, ErrorResponseRestDTO>,
) -> Response {
    let result = state
        .core
        .revocation_list_service
        .get_revocation_list_by_id(&id)
        .await;

    match result {
        Ok(result) => match result.get_content_type() {
            Some(content_type) => (
                StatusCode::OK,
                [(header::CONTENT_TYPE, content_type)],
                result.revocation_list,
            )
                .into_response(),
            None => {
                tracing::warn!("No content type for revocation-list: {id}");
                (StatusCode::OK, result.revocation_list).into_response()
            }
        },
        Err(error) if error.error_code() == ErrorCode::BR_0089 => {
            tracing::error!("Config validation error: {}", error);
            StatusCode::BAD_REQUEST.into_response()
        }
        Err(error) if error.error_code() == ErrorCode::BR_0034 => {
            tracing::warn!("Missing revocation list");
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
    path = "/ssi/revocation/v1/crl/{id}",
    params(
        ("id" = RevocationListId, Path, description = "Revocation list id")
    ),
    responses(
        (status = 200, description = "OK", content_type = "application/pkix-crl"),
        (status = 404, description = "Revocation list not found"),
        (status = 500, description = "Server error"),
    ),
    tag = "ssi",
    summary = "Revocation - retrieve CRL",
    description = indoc::formatdoc! {"
        Retrieve a CRL by its UUID.
    "},
)]
pub(crate) async fn get_crl_by_id(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<RevocationListId>, ErrorResponseRestDTO>,
) -> Response {
    let result = state.core.revocation_list_service.get_crl_by_id(&id).await;

    match result {
        Ok(result) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/pkix-crl")],
            result,
        )
            .into_response(),
        Err(error) if error.error_code() == ErrorCode::BR_0034 => {
            tracing::error!("Missing CRL");
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
    let result = state
        .core
        .ssi_issuer_service
        .get_json_ld_context(&id, None)
        .await;

    match result {
        Ok(value) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/ld+json")],
            Json(JsonLDContextResponseRestDTO::from(value)),
        )
            .into_response(),
        Err(error) if error.error_code() == ErrorCode::BR_0006 => {
            tracing::error!("Missing credential schema");
            (StatusCode::NOT_FOUND, "Missing credential schema").into_response()
        }
        Err(e @ (IssuerServiceError::InvalidInput | IssuerServiceError::InvalidFormat)) => {
            tracing::error!("Validation error: {e}");
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
    path = "/ssi/context/v1/{id}/{format}",
    params(
        ("id" = String, Path, description = "context id or credentialSchemaId"),
        ("format" = CredentialFormat, Path, description = "Credential schema format"),
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
pub(crate) async fn get_json_ld_context_by_format(
    state: State<AppState>,
    WithRejection(Path((id, format)), _): WithRejection<
        Path<(String, CredentialFormat)>,
        ErrorResponseRestDTO,
    >,
) -> Response {
    let result = state
        .core
        .ssi_issuer_service
        .get_json_ld_context(&id, Some(&format))
        .await;

    match result {
        Ok(value) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/ld+json")],
            Json(JsonLDContextResponseRestDTO::from(value)),
        )
            .into_response(),
        Err(error) if error.error_code() == ErrorCode::BR_0006 => {
            tracing::error!("Missing credential schema");
            (StatusCode::NOT_FOUND, "Missing credential schema").into_response()
        }
        Err(e @ (IssuerServiceError::InvalidInput | IssuerServiceError::InvalidFormat)) => {
            tracing::error!("Validation error: {e}");
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

#[endpoint(
    permissions = [],
    get,
    path = "/ssi/schema/v2/{id}",
    params(
        ("id" = CredentialSchemaId, Path, description = "Credential schema id"),
    ),
    responses(
        (status = 200, description = "OK", body = CredentialSchemaV2ResponseRestDTO),
        (status = 404, description = "Credential schema not found"),
        (status = 500, description = "Server error"),
    ),
    tag = "ssi",
    summary = "Retrieve credential schema v2 service",
    description = indoc::formatdoc! {"
        Retrieve a credential schema by its UUID in v2 format.
    "},
)]
pub(crate) async fn ssi_get_credential_schema_v2(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<CredentialSchemaId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<CredentialSchemaV2ResponseRestDTO> {
    let result = state
        .core
        .credential_schema_service
        .get_credential_schema_v2(&id, None)
        .await;

    OkOrErrorResponse::from_result(result, state, "getting credential schema v2")
}

#[endpoint(
    permissions = [],
    get,
    path = "/ssi/schema/v2/{id}/{format}",
    params(
        ("id" = CredentialSchemaId, Path, description = "Credential schema id"),
        ("format" = CredentialFormat, Path, description = "Credential schema format"),
    ),
    responses(
        (status = 200, description = "OK", body = CredentialSchemaV2ResponseRestDTO),
        (status = 404, description = "Credential schema not found"),
        (status = 500, description = "Server error"),
    ),
    tag = "ssi",
    summary = "Retrieve credential schema v2 service",
    description = indoc::formatdoc! {"
        Retrieve a credential schema by its UUID in v2 format.
    "},
)]
pub(crate) async fn ssi_get_credential_schema_by_format_v2(
    state: State<AppState>,
    WithRejection(Path((id, format)), _): WithRejection<
        Path<(CredentialSchemaId, CredentialFormat)>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<CredentialSchemaV2ResponseRestDTO> {
    let result = state
        .core
        .credential_schema_service
        .get_credential_schema_v2(&id, Some(&format))
        .await;

    OkOrErrorResponse::from_result(result, state, "getting credential schema v2")
}

#[endpoint(
    permissions = [],
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

#[endpoint(
    permissions = [],
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

#[endpoint(
    permissions = [],
    get,
    path = "/ssi/vct/v2/{organisationId}/{credentialSchemaId}/{format}",
    params(
        ("organisationId" = OrganisationId, Path, description = "Organization id"),
        ("credentialSchemaId" = String, Path, description = "Credential schema id"),
        ("format" = CredentialFormat, Path, description = "Credential format"),
    ),
    responses(
        (status = 200, description = "OK", body = SdJwtVcTypeMetadataResponseRestDTO),
        (status = 404, description = "Type metadata not found"),
        (status = 500, description = "Server error"),
    ),
    tag = "ssi",
    summary = "Retrieve SD-JWT VC type metadata v2 service",
    description = indoc::formatdoc! {"
        Retrieve the type metadata of an SD-JWT VC credential for a v2 schema.
    "},
)]
pub(crate) async fn ssi_get_sd_jwt_vc_type_metadata_v2(
    state: State<AppState>,
    WithRejection(Path((organisation_id, credential_schema_id, format)), _): WithRejection<
        Path<(OrganisationId, String, CredentialFormat)>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<SdJwtVcTypeMetadataResponseRestDTO> {
    let result = state
        .core
        .ssi_issuer_service
        .get_vct_metadata_v2(organisation_id, credential_schema_id, format)
        .await;
    OkOrErrorResponse::from_result(result, state, "getting SD-JWT VC type metadata v2")
}

#[endpoint(
    permissions = [],
    get,
    path = "/ssi/ca/{id}",
    params(
        ("id" = CertificateId, Path, description = "Certificate Authority id")
    ),
    responses(
        (status = 200, description = "OK", content_type = "application/pkix-cert"),
        (status = 404, description = "Certificate Authority not found"),
        (status = 500, description = "Server error"),
    ),
    tag = "ssi",
    summary = "Certificate Authority - retrieve certificate",
    description = indoc::formatdoc! {"
        Retrieve a Certificate Authority certificate by its UUID.
    "},
)]
pub(crate) async fn ssi_get_certificate_authority(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<CertificateId>, ErrorResponseRestDTO>,
) -> Response {
    let result = state
        .core
        .certificate_service
        .get_certificate_authority(id)
        .await;

    match result {
        Ok(result) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/pkix-cert")],
            result,
        )
            .into_response(),
        Err(error) if error.error_code() == ErrorCode::BR_0223 => {
            tracing::warn!("Missing CA");
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
    path = "/ssi/certificate/{id}",
    params(
        ("id" = CertificateId, Path, description = "Certificate id")
    ),
    responses(
        (status = 200, description = "OK", content(
            (String = "application/pem-certificate-chain", example = "-----BEGIN CERTIFICATE-----\nMIICY...\n-----END CERTIFICATE-----"),
            ([u8] = "application/cose-x509")
        )),
        (status = 404, description = "Certificate not found"),
        (status = 500, description = "Server error"),
    ),
    tag = "ssi",
    summary = "Certificate - retrieve certificate",
    description = indoc::formatdoc! {"
        Retrieve a certificate by its UUID.
    "},
)]
pub(crate) async fn ssi_get_certificate(
    accept: Option<TypedHeader<Accept>>,
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<CertificateId>, ErrorResponseRestDTO>,
) -> Response {
    // fallback to PEM format if no accept header recognized
    let format = if let Some(TypedHeader(accept)) = accept {
        accept
            .negotiate(&[
                (&APPLICATION_PEM_CHAIN, CertificateFormatEnum::Pem),
                (&APPLICATION_COSE_X509, CertificateFormatEnum::CoseX509),
            ])
            .unwrap_or(CertificateFormatEnum::Pem)
    } else {
        CertificateFormatEnum::Pem
    };

    let result = state
        .core
        .certificate_service
        .get_certificate_content(id, format)
        .await;

    match result {
        Ok(content) => {
            let content_type = match format {
                CertificateFormatEnum::Pem => APPLICATION_PEM_CHAIN.as_ref(),
                CertificateFormatEnum::CoseX509 => "application/cose-x509; usage=chain",
            };

            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, content_type)],
                content,
            )
                .into_response()
        }
        Err(error) if error.error_code() == ErrorCode::BR_0223 => {
            tracing::warn!("Missing certificate");
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
    path = "/ssi/trust-list/v1/{id}",
    params(
        ("id" = TrustListPublicationId, Path, description = "Trust list publication id")
    ),
    responses(
        (status = 200, description = "OK", content(
            (String = "application/jwt"),
            (String = "application/xml")
        )),
        (status = 404, description = "Trust list publication not found"),
        (status = 406, description = "Unsupported Accept content type"),
        (status = 500, description = "Server error"),
    ),
    tag = "ssi",
    summary = "Retrieve Trust list publication",
    description = indoc::formatdoc! {"
        Retrieve a Trust list publication by its UUID.
        Use the Accept header to request a specific format (application/jwt or application/xml).
    "},
)]
pub(crate) async fn ssi_get_trust_list_publication(
    accept: Option<TypedHeader<Accept>>,
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<TrustListPublicationId>, ErrorResponseRestDTO>,
) -> Response {
    // an absent Accept header leaves the content type up to the publisher, as does a
    // wildcard, which matches both of the content types offered below
    let accepted_content_types = if let Some(TypedHeader(accept)) = accept {
        let accepted_content_types = accept.negotiate_all(&[
            (&APPLICATION_JWT, TrustListContentTypeDTO::Jwt),
            (&APPLICATION_XML, TrustListContentTypeDTO::Xml),
        ]);

        if accepted_content_types.is_empty() {
            return StatusCode::NOT_ACCEPTABLE.into_response();
        }

        accepted_content_types
    } else {
        vec![]
    };

    let result = state
        .core
        .trust_list_publication_service
        .get_trust_list_publication_content(id, &accepted_content_types)
        .await;

    match result {
        Ok(result) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, result.content_type.to_string())],
            result.content,
        )
            .into_response(),
        Err(error) if error.error_code() == ErrorCode::BR_0383 => {
            tracing::warn!("Missing trust list publication");
            StatusCode::NOT_FOUND.into_response()
        }
        Err(TrustListPublicationServiceError::UnsupportedAcceptType(_)) => {
            StatusCode::NOT_ACCEPTABLE.into_response()
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
    path = "/ssi/trust-collection/v1/{id}",
    params(
        ("id" = TrustCollectionId, Path, description = "Trust collection id")
    ),
    responses(
        (status = 200, description = "OK", body = TrustCollectionResponseRestDTO),
        (status = 404, description = "Trust collection not found"),
        (status = 500, description = "Server error"),
    ),
    tag = "ssi",
    summary = "Retrieve Trust collection",
    description = indoc::formatdoc! {"
        Retrieve a Trust collection by its UUID.
    "},
)]
pub(crate) async fn ssi_get_trust_collection(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<TrustCollectionId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<TrustCollectionResponseRestDTO> {
    let result = state
        .core
        .trust_collection_service
        .get_public_trust_collection(id)
        .await;
    OkOrErrorResponse::from_result(result, state, "getting trust collection data")
}
