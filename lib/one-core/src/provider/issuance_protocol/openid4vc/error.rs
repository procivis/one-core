use thiserror::Error;

use crate::model::credential::CredentialStateEnum;

#[derive(Clone, Debug, Error)]
pub enum OpenID4VCIError {
    #[error("unsupported_grant_type")]
    UnsupportedGrantType,
    #[error("invalid_grant")]
    InvalidGrant,
    #[error("invalid_request")]
    InvalidRequest,
    #[error("invalid_token")]
    InvalidToken,
    #[error("invalid_or_missing_proof")]
    InvalidOrMissingProof,
    #[error("unsupported_credential_format")]
    UnsupportedCredentialFormat,
    #[error("unsupported_credential_type")]
    UnsupportedCredentialType,
    #[error("credential_request_denied")]
    CredentialRequestDenied,
    #[error("oidc runtime error: `{0}`")]
    RuntimeError(String),
}

#[derive(Debug, Error)]
pub enum OpenIDIssuanceError {
    #[error("Invalid credential state: `{state}`")]
    InvalidCredentialState { state: CredentialStateEnum },

    #[error("Validation error: `{0}`")]
    ValidationError(String),

    #[error("OpenID4VCI error: `{0}`")]
    OpenID4VCI(#[from] OpenID4VCIError),
}
