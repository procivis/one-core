use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(Debug, Error)]
pub enum HolderWalletUnitError {
    #[error("Wallet unit revoked")]
    WalletUnitRevoked,

    #[error(
        "App integrity check required: proof and public key must only be provided on wallet unit activation"
    )]
    AppIntegrityCheckRequired,

    #[error("App integrity check not required: provide proof and public key")]
    AppIntegrityCheckNotRequired,

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for HolderWalletUnitError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::WalletUnitRevoked => ErrorCode::BR_0261,
            Self::AppIntegrityCheckRequired => ErrorCode::BR_0280,
            Self::AppIntegrityCheckNotRequired => ErrorCode::BR_0281,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
