//! Enumerates errors related to revocation method provider.

use shared_types::{CredentialId, IdentifierId};
use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::credential::CredentialStateEnum;
use crate::model::did::KeyRole;
use crate::model::identifier::IdentifierType;

#[derive(Debug, Error)]
pub enum RevocationError {
    #[error("Credential not found: `{0}`")]
    CredentialNotFound(CredentialId),
    #[error("Formatter not found: `{0}`")]
    FormatterNotFound(String),
    #[error("Invalid credential state: `{0}`")]
    InvalidCredentialState(CredentialStateEnum),
    #[error("Invalid identifier type: `{0}`")]
    InvalidIdentifierType(IdentifierType),
    #[error("Invalid key algorithm: `{0}`")]
    InvalidKeyAlgorithm(String),
    #[error("Key with role `{0}` not found`")]
    KeyWithRoleNotFound(KeyRole),
    #[error("Mapping error: `{0}`")]
    MappingError(String),
    #[error("Missing credential `{0}` index on revocation list for identifier id `{1}`")]
    MissingCredentialIndexOnRevocationList(CredentialId, IdentifierId),
    #[error("Operation not supported: `{0}`")]
    OperationNotSupported(String),
    #[error("Validation error: `{0}`")]
    ValidationError(String),

    #[error("From UTF-8 error: `{0}`")]
    FromUtf8Error(#[from] std::string::FromUtf8Error),
    #[error("JSON error: `{0}`")]
    JsonError(#[from] serde_json::Error),
    #[error("X509 error: `{0}`")]
    X509Error(#[from] rcgen::Error),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for RevocationError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::Nested(nested) => nested.error_code(),
            _ => ErrorCode::BR_0101,
        }
    }
}
