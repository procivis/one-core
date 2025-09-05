use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::service::error::{ErrorCode, ErrorCodeMixin};

pub mod hce;
pub mod scanner;

#[derive(Debug, Error, Serialize, Deserialize, Clone)]
pub enum NfcError {
    #[error("NFC Adapter not enabled")]
    NotEnabled,
    #[error("The device does not support NFC")]
    NotSupported,
    #[error("Already started")]
    AlreadyStarted,
    #[error("Not started")]
    NotStarted,
    #[error("Operation cancelled")]
    Cancelled,
    #[error("Session closed")]
    SessionClosed,
    #[error("Unknown NFC error: {reason}")]
    Unknown { reason: String },
}

impl ErrorCodeMixin for NfcError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::NotEnabled => ErrorCode::BR_0273,
            Self::NotSupported => ErrorCode::BR_0274,
            Self::AlreadyStarted => ErrorCode::BR_0275,
            Self::NotStarted => ErrorCode::BR_0276,
            Self::Cancelled => ErrorCode::BR_0277,
            Self::SessionClosed => ErrorCode::BR_0278,
            Self::Unknown { .. } => ErrorCode::BR_0000,
        }
    }
}
