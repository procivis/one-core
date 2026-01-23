use shared_types::{KeyId, OrganisationId};
use thiserror::Error;

use crate::config::core_config::KeyAlgorithmType;
use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(Debug, Error)]
pub enum KeyServiceError {
    #[error("Organisation `{0}` not found")]
    MissingOrganisation(OrganisationId),
    #[error("Organisation `{0}` is deactivated")]
    OrganisationDeactivated(OrganisationId),
    #[error("Key `{0}` not found")]
    KeyNotFound(KeyId),
    #[error("Key already exists")]
    KeyAlreadyExists,
    #[error("Invalid key storage: `{key_storage}`")]
    InvalidKeyStorage { key_storage: String },
    #[error("Invalid key algorithm: `{key_algorithm}`")]
    InvalidKeyAlgorithm { key_algorithm: String },
    #[error("Unsupported key type: `{key_type}`")]
    UnsupportedKeyType { key_type: KeyAlgorithmType },
    #[error("Mapping error: {0}")]
    MappingError(String),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for KeyServiceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MissingOrganisation(_) => ErrorCode::BR_0088,
            Self::OrganisationDeactivated(_) => ErrorCode::BR_0241,
            Self::KeyNotFound(_) => ErrorCode::BR_0037,
            Self::KeyAlreadyExists => ErrorCode::BR_0004,
            Self::InvalidKeyStorage { .. } => ErrorCode::BR_0041,
            Self::InvalidKeyAlgorithm { .. } => ErrorCode::BR_0043,
            Self::UnsupportedKeyType { .. } => ErrorCode::BR_0039,
            Self::MappingError(_) => ErrorCode::BR_0000,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
