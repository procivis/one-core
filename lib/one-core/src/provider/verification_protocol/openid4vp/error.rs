use thiserror::Error;

use crate::validator::TimestampValidationError;

#[derive(Debug, Error)]
pub enum OpenID4VCError {
    #[error("Credential is revoked or suspended")]
    CredentialIsRevokedOrSuspended,
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
    #[error("Timestamp validation error: `{0}`")]
    TimestampValidation(#[from] TimestampValidationError),

    #[error("invalid_request")]
    InvalidRequest,

    #[error("Invalid proof state: `{0}`")]
    InvalidProofState(String),

    #[error("vp_formats_not_supported")]
    VPFormatsNotSupported,
    #[error("vc_formats_not_supported")]
    VCFormatsNotSupported,
}
