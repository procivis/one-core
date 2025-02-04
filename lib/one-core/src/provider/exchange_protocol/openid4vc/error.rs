use thiserror::Error;

use crate::model::credential::CredentialStateEnum;
use crate::provider::revocation::error::RevocationError;

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
    #[error("vp_formats_not_supported")]
    VPFormatsNotSupported,
    #[error("vc_formats_not_supported")]
    VCFormatsNotSupported,
    #[error("credential_request_denied")]
    CredentialRequestDenied,
    #[error("oidc runtime error: `{0}`")]
    RuntimeError(String),
}

#[derive(Debug, Error)]
pub enum OpenID4VCError {
    #[error("Credential is revoked or suspended")]
    CredentialIsRevokedOrSuspended,
    #[error("Invalid credential state: `{state}`")]
    InvalidCredentialState { state: CredentialStateEnum },
    #[error("Mapping error: `{0}`")]
    MappingError(String),
    #[error("Missing claim schemas")]
    MissingClaimSchemas,
    #[error("Missing revocation provider for type: `{0}`")]
    MissingRevocationProviderForType(String),
    #[error("Other: `{0}`")]
    Other(String),
    #[error("Validation error: `{0}`")]
    ValidationError(String),

    #[error("OpenID4VCI error: `{0}`")]
    OpenID4VCI(#[from] OpenID4VCIError),
    #[error("Revocation error: `{0}`")]
    Revocation(#[from] RevocationError),
}
