use serde::{Deserialize, Serialize};
use thiserror::Error;

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
