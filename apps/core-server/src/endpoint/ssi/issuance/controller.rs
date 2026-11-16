use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::WithRejection;
use one_core::error::{ErrorCode, ErrorCodeMixin};
use one_core::service::ssi_issuer::error::IssuerServiceError;
use proc_macros::endpoint;
use shared_types::{CredentialSchemaId, IdentifierId, IssuanceProtocolId};

use crate::dto::error::ErrorResponseRestDTO;
use crate::endpoint::ssi::issuance::dto::SdJwtVcIssuerMetadataRestDTO;
use crate::router::AppState;

#[endpoint(
    permissions = [],
    get,
    path = "/.well-known/jwt-vc-issuer/ssi/openid4vci/{protocol_id}/{identifier_id}/{credential_schema_id}",
    params(
        ("protocol_id" = String, Path, description = "Issuance protocol id"),
        ("identifier_id" = IdentifierId, Path, description = "Identifier id"),
        ("credential_schema_id" = CredentialSchemaId, Path, description = "Credential schema id")
    ),
    responses(
        (status = 200, description = "OK", body = SdJwtVcIssuerMetadataRestDTO),
        (status = 404, description = "Issuer not found"),
        (status = 500, description = "Server error"),
    ),
    tag = "openid4vci",
    summary = "OID4VC - Retrieve SD-JWT VC Issuer metadata",
    description = indoc::formatdoc! {"
        Returns JWT VC Issuer Metadata, including the issuer identifier
        and the JSON Web Key Set (JWKS) containing the public keys used
        to sign issued credentials.
    "},
)]
pub(crate) async fn oid4vci_get_jwt_vc_issuer_metadata(
    state: State<AppState>,
    WithRejection(Path((protocol_id, identifier_id, credential_schema_id)), _): WithRejection<
        Path<(IssuanceProtocolId, IdentifierId, CredentialSchemaId)>,
        ErrorResponseRestDTO,
    >,
) -> Response {
    let result = state
        .core
        .ssi_issuer_service
        .get_sd_jwt_vc_issuer_metadata(&protocol_id, &identifier_id, &credential_schema_id)
        .await;

    match result {
        Ok(value) => {
            let response_body: SdJwtVcIssuerMetadataRestDTO = value.into();
            (StatusCode::OK, Json(response_body)).into_response()
        }
        Err(error @ IssuerServiceError::MissingProtocol(_)) => {
            tracing::error!("Not found error: {error}");
            StatusCode::NOT_FOUND.into_response()
        }
        Err(error) if matches!(error.error_code(), ErrorCode::BR_0006 | ErrorCode::BR_0207) => {
            tracing::error!("Not found error: {error}");
            StatusCode::NOT_FOUND.into_response()
        }
        Err(e) => {
            tracing::error!("Error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
