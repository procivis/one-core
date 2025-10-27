use one_core::OneCoreBuildError;
use one_core::provider::key_storage::error::KeyStorageError;
use one_core::service::error::ErrorCodeMixin;
use one_crypto::SignerError;
use one_dto_mapper::{From, Into};
use strum::EnumMessage;
use thiserror::Error;

#[derive(Debug, Error)]
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

impl From<OneCoreBuildError> for SDKError {
    fn from(err: OneCoreBuildError) -> Self {
        SDKError::InitializationFailure(err.to_string())
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ErrorResponseBindingDTO {
    pub code: String,
    pub message: String,
    pub cause: Option<Cause>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct Cause {
    pub message: String,
}

impl Cause {
    pub(crate) fn with_message_from_error(error: &impl std::error::Error) -> Cause {
        Cause {
            message: error.to_string(),
        }
    }
}

#[derive(Error, Debug, uniffi::Error)]
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
    #[allow(dead_code)]
    pub(crate) fn hide_cause(mut self, hide: bool) -> ErrorResponseBindingDTO {
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
            code: Into::<&'static str>::into(code).to_string(),
            message: code.get_message().unwrap_or_default().to_string(),
            cause: Some(cause),
        }
    }
}

#[derive(Debug, Error, uniffi::Error)]
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

#[derive(Debug, Clone, From, Into, Error, uniffi::Error)]
#[from(one_core::proto::bluetooth_low_energy::BleError)]
#[into(one_core::proto::bluetooth_low_energy::BleError)]
pub enum BleError {
    #[error("BLE adapter not enabled")]
    AdapterNotEnabled,
    #[error("BLE scan already started")]
    ScanAlreadyStarted,
    #[error("BLE scan not started")]
    ScanNotStarted,
    #[error("Advertisement already started")]
    BroadcastAlreadyStarted,
    #[error("Advertisement not started")]
    BroadcastNotStarted,
    #[error("Another write or read operation is in progress")]
    AnotherOperationInProgress,
    #[error("Data too long")]
    WriteDataTooLong,
    #[error("No device with address {address} found")]
    DeviceAddressNotFound { address: String },
    #[error("Service with UUID {service} not found")]
    ServiceNotFound { service: String },
    #[error("Characteristic with UUID {characteristic} not found")]
    CharacteristicNotFound { characteristic: String },
    #[error("Invalid UUID: {uuid}")]
    InvalidUUID { uuid: String },
    #[error("Not connected to device {address}")]
    DeviceNotConnected { address: String },
    #[error(
        "Operation {operation} can not be performed on characteristic {characteristic}, service UUID {service}"
    )]
    InvalidCharacteristicOperation {
        service: String,
        characteristic: String,
        operation: String,
    },
    #[error("The device does not support BLE")]
    NotSupported,
    #[error("Application not authorized to use BLE")]
    NotAuthorized,
    #[error("GATT server not running")]
    ServerNotRunning,
    #[error("Unknown BLE error: {reason}")]
    Unknown { reason: String },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for BleError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Unknown {
            reason: e.to_string(),
        }
    }
}

#[derive(Debug, Clone, From, Into, Error, uniffi::Error)]
#[from(one_core::proto::nfc::NfcError)]
#[into(one_core::proto::nfc::NfcError)]
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

impl From<uniffi::UnexpectedUniFFICallbackError> for NfcError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Unknown {
            reason: e.to_string(),
        }
    }
}
