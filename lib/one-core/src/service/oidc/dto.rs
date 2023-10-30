use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

#[derive(Clone, Debug)]
pub struct OpenID4VCIIssuerMetadataResponseDTO {
    pub credential_issuer: String,
    pub credential_endpoint: String,
    pub credentials_supported: Vec<OpenID4VCIIssuerMetadataCredentialSupportedResponseDTO>,
}
#[derive(Clone, Debug)]
pub struct OpenID4VCIIssuerMetadataCredentialSupportedResponseDTO {
    pub format: String,
    pub credential_definition: OpenID4VCIIssuerMetadataCredentialDefinitionResponseDTO,
}

#[derive(Clone, Debug)]
pub struct OpenID4VCIIssuerMetadataCredentialDefinitionResponseDTO {
    pub r#type: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct OpenID4VCIDiscoveryResponseDTO {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(transparent)]
pub struct DurationSeconds(pub i64);

pub struct OpenID4VCITokenResponseDTO {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: DurationSeconds,
}

#[derive(Clone, Debug)]
pub struct OpenID4VCIErrorResponseDTO {
    pub error: OpenID4VCIError,
}

#[derive(Clone, Debug)]
pub struct OpenID4VCITokenRequestDTO {
    pub grant_type: String,
    pub pre_authorized_code: String,
}
#[derive(Clone, Debug, PartialEq, Error)]
pub enum OpenID4VCIError {
    #[error("unsupported_grant_type")]
    UnsupportedGrantType,
    #[error("invalid_grant")]
    InvalidGrant,
    #[error("invalid_request")]
    InvalidRequest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenID4VCIInteractionDataDTO {
    pub pre_authorized_code_used: bool,
    pub access_token: String,
    #[serde(with = "time::serde::rfc3339")]
    pub access_token_expires_at: OffsetDateTime,
}
