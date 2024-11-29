use one_core::provider::bluetooth_low_energy::BleError;
use one_core::provider::key_storage::error::KeyStorageError;
use one_core::service::error::ErrorCodeMixin;
use one_crypto::SignerError;
use thiserror::Error;

use super::error_code::ErrorCode;

#[derive(Debug, thiserror::Error)]
pub(crate) enum SDKError {
    #[error("Initialization failure: {0}")]
    InitializationFailure(String),

    #[error("Not initialized")]
    NotInitialized,
}

impl ErrorCodeMixin for SDKError {
    fn error_code(&self) -> one_core::service::error::ErrorCode {
        match self {
            Self::InitializationFailure(_) => one_core::service::error::ErrorCode::BR_0183,
            Self::NotInitialized => one_core::service::error::ErrorCode::BR_0184,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ErrorResponseBindingDTO {
    pub code: String,
    pub message: String,
    pub cause: Option<Cause>,
}

#[derive(Debug, Clone)]
pub struct Cause {
    pub message: String,
}

impl Cause {
    pub fn with_message_from_error(error: &impl std::error::Error) -> Cause {
        Cause {
            message: error.to_string(),
        }
    }
}

#[derive(Error, Debug)]
pub enum BindingError {
    #[error("Error: {data:?}")]
    ErrorResponse { data: ErrorResponseBindingDTO },
}

impl<T: Into<ErrorResponseBindingDTO>> From<T> for BindingError {
    fn from(value: T) -> Self {
        Self::ErrorResponse { data: value.into() }
    }
}

impl ErrorResponseBindingDTO {
    pub fn hide_cause(mut self, hide: bool) -> ErrorResponseBindingDTO {
        if hide {
            self.cause = None;
        }

        self
    }
}

impl<T: ErrorCodeMixin + std::error::Error> From<T> for ErrorResponseBindingDTO {
    fn from(error: T) -> Self {
        let code = error.error_code();
        let cause = Cause::with_message_from_error(&error);

        ErrorResponseBindingDTO {
            code: ErrorCode::from(code).to_string(),
            message: code.to_string(),
            cause: Some(cause),
        }
    }
}

#[derive(Debug, Error)]
pub enum NativeKeyStorageError {
    #[error("Failed to generate key: {reason:?}")]
    KeyGenerationFailure { reason: String },
    #[error("Failed to crate signature: {reason:?}")]
    SignatureFailure { reason: String },
    #[error("Unsupported")]
    Unsupported,
    #[error("Unknown error: {reason:?}")]
    Unknown { reason: String },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for NativeKeyStorageError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Unknown {
            reason: e.to_string(),
        }
    }
}

impl From<NativeKeyStorageError> for KeyStorageError {
    fn from(error: NativeKeyStorageError) -> Self {
        match &error {
            NativeKeyStorageError::Unsupported => {
                Self::NotSupported("Unsupported by native storage".to_string())
            }
            _ => Self::Failed(error.to_string()),
        }
    }
}

impl From<NativeKeyStorageError> for SignerError {
    fn from(error: NativeKeyStorageError) -> Self {
        match &error {
            NativeKeyStorageError::SignatureFailure { reason } => {
                SignerError::CouldNotSign(format!("Native signature failed: {reason}"))
            }
            _ => Self::CouldNotSign(error.to_string()),
        }
    }
}

// BleError is defined in core, we need to implement UnexpectedUniFFICallbackError for it
// therefore the wrapper

#[derive(Debug, Error)]
#[error(transparent)]
pub enum BleErrorWrapper {
    Ble { error: BleError },
}

impl From<BleError> for BleErrorWrapper {
    fn from(error: BleError) -> Self {
        Self::Ble { error }
    }
}

impl From<BleErrorWrapper> for BleError {
    fn from(error: BleErrorWrapper) -> Self {
        match error {
            BleErrorWrapper::Ble { error } => error,
        }
    }
}

impl From<uniffi::UnexpectedUniFFICallbackError> for BleErrorWrapper {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Ble {
            error: BleError::Unknown {
                reason: e.to_string(),
            },
        }
    }
}
