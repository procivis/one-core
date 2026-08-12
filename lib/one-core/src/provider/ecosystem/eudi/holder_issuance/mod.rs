use std::sync::Arc;

use thiserror::Error;
use time::Duration;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::proto::session_provider::SessionProvider;
use crate::proto::wrp_validator::WRPValidator;
use crate::provider::blob_storage::provider::BlobStorageProvider;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::interaction_repository::InteractionRepository;

mod credential;
mod metadata;

#[derive(Debug, Error)]
pub(crate) enum HolderIssuanceError {
    #[error("Missing registry URL")]
    MissingRegistryUrl,
    #[error("Missing identifier")]
    MissingIdentifier,
    #[error("Disallowed credential configuration")]
    DisallowedCredentialConfiguration,
    #[error("Inconsistent trust info")]
    InconsistentTrustInfo,
    #[error("No credential configuration")]
    NoCredentialConfiguration,
    #[error("Invalid credential configuration: `{0}`")]
    InvalidCredentialConfiguration(String),

    #[error("Mapping error: `{0}`")]
    MappingError(String),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for HolderIssuanceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MissingRegistryUrl
            | Self::MissingIdentifier
            | Self::InconsistentTrustInfo
            | Self::NoCredentialConfiguration
            | Self::InvalidCredentialConfiguration(_) => ErrorCode::BR_0477,
            Self::DisallowedCredentialConfiguration => ErrorCode::BR_0411,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}

pub(crate) struct HolderIssuanceResolver {
    history_repository: Arc<dyn HistoryRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    wrp_validator: Arc<dyn WRPValidator>,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
    session_provider: Arc<dyn SessionProvider>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    leeway: Duration,
}

impl HolderIssuanceResolver {
    pub(crate) fn new(
        history_repository: Arc<dyn HistoryRepository>,
        interaction_repository: Arc<dyn InteractionRepository>,
        wrp_validator: Arc<dyn WRPValidator>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
        session_provider: Arc<dyn SessionProvider>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        leeway: Duration,
    ) -> Self {
        Self {
            history_repository,
            interaction_repository,
            wrp_validator,
            blob_storage_provider,
            session_provider,
            formatter_provider,
            leeway,
        }
    }
}
