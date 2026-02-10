//! Enumerates errors related to revocation method provider.

use shared_types::{CredentialId, IdentifierId};
use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::credential::CredentialStateEnum;
use crate::model::did::KeyRole;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::did_method::error::DidMethodProviderError;
use crate::provider::key_storage::error::KeyStorageProviderError;
use crate::provider::revocation::bitstring_status_list::util::BitstringError;
use crate::provider::revocation::token_status_list::util::TokenError;
use crate::repository::error::DataLayerError;

#[derive(Debug, Error)]
pub enum RevocationError {
    #[error("Credential not found: `{0}`")]
    CredentialNotFound(CredentialId),
    #[error("Formatter not found: `{0}`")]
    FormatterNotFound(String),
    #[error("Invalid credential state: `{0}`")]
    InvalidCredentialState(CredentialStateEnum),
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

    #[error("Bitstring error: `{0}`")]
    BitstringError(#[from] BitstringError),
    #[error("Did method provider error: `{0}`")]
    DidMethodProviderError(#[from] DidMethodProviderError),
    #[error("Formatter error: `{0}`")]
    FormatterError(#[from] FormatterError),
    #[error("Key storage provider error: `{0}`")]
    KeyStorageProviderError(#[from] KeyStorageProviderError),
    #[error("Token error: `{0}`")]
    TokenError(#[from] TokenError),
    #[error("From UTF-8 error: `{0}`")]
    FromUtf8Error(#[from] std::string::FromUtf8Error),
    #[error("JSON error: `{0}`")]
    JsonError(#[from] serde_json::Error),
    #[error("Data layer error: `{0}`")]
    DataLayerError(#[from] DataLayerError),

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
