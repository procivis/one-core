use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::provider::wallet_provider_client::error::WalletProviderClientError;

#[derive(Debug, Error)]
pub enum HolderWalletUnitError {
    #[error("Wallet unit revoked")]
    WalletUnitRevoked,

    #[error("Wallet unit client failure: {0}")]
    WalletProviderClientFailure(#[from] WalletProviderClientError),

    #[error(
        "App integrity check required: proof and public key must only be provided on wallet unit activation"
    )]
    AppIntegrityCheckRequired,

    #[error("App integrity check not required: provide proof and public key")]
    AppIntegrityCheckNotRequired,
}

impl ErrorCodeMixin for HolderWalletUnitError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::WalletUnitRevoked => ErrorCode::BR_0261,
            Self::WalletProviderClientFailure(_) => ErrorCode::BR_0264,
            Self::AppIntegrityCheckRequired => ErrorCode::BR_0280,
            Self::AppIntegrityCheckNotRequired => ErrorCode::BR_0281,
        }
    }
}
