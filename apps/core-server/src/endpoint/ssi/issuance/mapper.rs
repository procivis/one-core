use std::str::FromStr;

use axum::Json;
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use headers::Mime;
use one_core::service::oid4vci_final1_0::dto::{
    CredentialRequestPayload, CredentialResponsePayload,
};
use one_core::service::ssi_issuer::dto::{SdJwtVcIssuerMetadata, SdJwtVcIssuerMetadataJwks};

use crate::endpoint::ssi::dto::{OpenID4VCIErrorResponseRestDTO, OpenID4VCIErrorRestEnum};
use crate::endpoint::ssi::issuance::dto::{
    SdJwtVcIssuerMetadataJwksRestDTO, SdJwtVcIssuerMetadataRestDTO,
};
use crate::endpoint::ssi::issuance::final1_0::dto::OpenID4VCIFinal1CredentialResponseRestDTO;
use crate::headers::APPLICATION_JWT;

impl From<SdJwtVcIssuerMetadata> for SdJwtVcIssuerMetadataRestDTO {
    fn from(o: SdJwtVcIssuerMetadata) -> Self {
        let (jwks, jwks_uri) = match o.jwks {
            SdJwtVcIssuerMetadataJwks::Jwks(jwks) => {
                (Some(SdJwtVcIssuerMetadataJwksRestDTO { keys: jwks }), None)
            }
            SdJwtVcIssuerMetadataJwks::JwksUri(jwks_uri) => (None, Some(jwks_uri)),
        };
        Self {
            issuer: o.issuer,
            jwks_uri,
            jwks,
        }
    }
}

/// Reads a Credential Request body, which is either plain JSON or - when encrypted - a compact
/// serialized JWE sent as `application/jwt`.
///
/// Returns the error response to send back when the body cannot be read.
pub(crate) fn parse_credential_request(
    headers: &HeaderMap,
    body: Bytes,
) -> Result<CredentialRequestPayload, Box<Response>> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .map(|value| {
            value
                .to_str()
                .ok()
                .and_then(|value| Mime::from_str(value).ok())
                .ok_or_else(|| Box::new(StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response()))
        })
        .transpose()?;

    match content_type {
        Some(content_type) if content_type.essence_str() == APPLICATION_JWT.essence_str() => {
            String::from_utf8(body.into())
                .map(CredentialRequestPayload::Encrypted)
                .map_err(|error| {
                    tracing::error!("Credential request JWE is not valid UTF-8: {error}");
                    invalid_credential_request()
                })
        }
        // no content type means we fall back to JSON, as the specification mandates it for
        // unencrypted requests
        Some(content_type)
            if content_type.essence_str() != mime::APPLICATION_JSON.essence_str() =>
        {
            Err(Box::new(StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response()))
        }
        _ => serde_json::from_slice(&body)
            .map(|request| CredentialRequestPayload::Plain(Box::new(request)))
            .map_err(|error| {
                tracing::error!("Failed parsing credential request: {error}");
                invalid_credential_request()
            }),
    }
}

fn invalid_credential_request() -> Box<Response> {
    Box::new(
        (
            StatusCode::BAD_REQUEST,
            Json(OpenID4VCIErrorResponseRestDTO {
                error: OpenID4VCIErrorRestEnum::InvalidRequest,
                error_description: None,
            }),
        )
            .into_response(),
    )
}

/// Renders a Credential Response, as JSON or - when the wallet asked for encryption - as a compact
/// serialized JWE sent as `application/jwt`.
pub(crate) fn credential_response(response: CredentialResponsePayload) -> Response {
    match response {
        CredentialResponsePayload::Plain(response) => (
            StatusCode::OK,
            Json(OpenID4VCIFinal1CredentialResponseRestDTO::from(*response)),
        )
            .into_response(),
        CredentialResponsePayload::Encrypted(jwe) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, APPLICATION_JWT.as_ref())],
            jwe,
        )
            .into_response(),
    }
}
