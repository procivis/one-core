use shared_types::IdentifierId;
use thiserror::Error;
use uuid::Uuid;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::identifier::IdentifierType;

#[derive(Debug, Error)]
pub enum SignatureServiceError {
    #[error("Missing provider for signature type `{0}`")]
    MissingSignerProvider(String),
    #[error("Invalid signature id {0}")]
    InvalidSignatureId(Uuid),
    #[error("Identifier {0} not found")]
    IdentifierNotFound(IdentifierId),
    #[error("Identifier type `{0}` not supported")]
    UnsupportedIdentifierType(IdentifierType),
    #[error("Revocation not supported")]
    RevocationNotSupported,
    #[error("Mapping error: {0}")]
    MappingError(String),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for SignatureServiceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MissingSignerProvider { .. } => ErrorCode::BR_0326,
            Self::InvalidSignatureId(_) => ErrorCode::BR_0327,
            Self::UnsupportedIdentifierType(_) => ErrorCode::BR_0330,
            Self::IdentifierNotFound(_) => ErrorCode::BR_0207,
            Self::RevocationNotSupported => ErrorCode::BR_0101,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
