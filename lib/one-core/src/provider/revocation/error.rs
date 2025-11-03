//! Enumerates errors related to revocation method provider.

use shared_types::{CredentialId, IdentifierId};
use thiserror::Error;

use crate::model::credential::CredentialStateEnum;
use crate::model::did::KeyRole;
use crate::proto::http_client;
use crate::provider::caching_loader::ResolverError;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::did_method::error::DidMethodProviderError;
use crate::provider::key_storage::error::KeyStorageProviderError;
use crate::provider::remote_entity_storage::RemoteEntityStorageError;
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
    #[error("Missing credential index `{0}` on revocation list for identifier id `{1}`")]
    MissingCredentialIndexOnRevocationList(CredentialId, IdentifierId),
    #[error("Operation not supported: `{0}`")]
    OperationNotSupported(String),
    #[error("Validation error: `{0}`")]
    ValidationError(String),

    #[error("Bitstring error: `{0}`")]
    BitstringError(#[from] BitstringError),
    #[error("Resolver error: `{0}`")]
    ResolverError(#[from] ResolverError),
    #[error("Did method provider error: `{0}`")]
    DidMethodProviderError(#[from] DidMethodProviderError),
    #[error("Formatter error: `{0}`")]
    FormatterError(#[from] FormatterError),
    #[error("Key storage provider error: `{0}`")]
    KeyStorageProviderError(#[from] KeyStorageProviderError),
    #[error("Remote entity storage error: `{0}`")]
    RemoteEntityStorageError(#[from] RemoteEntityStorageError),
    #[error("Token error: `{0}`")]
    TokenError(#[from] TokenError),

    #[error("From UTF-8 error: `{0}`")]
    FromUtf8Error(#[from] std::string::FromUtf8Error),
    #[error("HTTP client error: `{0}`")]
    HttpClientError(#[from] http_client::Error),
    #[error("JSON error: `{0}`")]
    JsonError(#[from] serde_json::Error),
    #[error("Data layer error: `{0}`")]
    DataLayerError(#[from] DataLayerError),
}
