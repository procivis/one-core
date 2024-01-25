use one_core::{
    config::{ConfigError, ConfigParsingError},
    provider::transport_protocol::TransportProtocolError,
    service::error::{BusinessLogicError, ServiceError},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BindingError {
    #[error("Already exists: `{0}`")]
    AlreadyExists(String),
    #[error("Not found: `{0}`")]
    NotFound(String),
    #[error("Not supported: `{0}`")]
    NotSupported(String),
    #[error("Validation error: `{0}`")]
    ValidationError(String),
    #[error("Config validation error `{0}`")]
    ConfigValidationError(String),
    #[error("Core uninitialized")]
    Uninitialized,
    #[error("Unknown error: `{0}`")]
    Unknown(String),
}

impl From<ServiceError> for BindingError {
    fn from(error: ServiceError) -> Self {
        match &error {
            ServiceError::EntityNotFound(error) => Self::NotFound(error.to_string()),
            ServiceError::ValidationError(_) => Self::ValidationError(error.to_string()),
            ServiceError::ConfigValidationError(_) => {
                Self::ConfigValidationError(error.to_string())
            }
            ServiceError::TransportProtocolError(e) => match e {
                TransportProtocolError::OperationNotSupported => {
                    Self::NotSupported(error.to_string())
                }
                error => Self::Unknown(error.to_string()),
            },
            ServiceError::BusinessLogic(e) => match e {
                BusinessLogicError::OrganisationAlreadyExists => {
                    Self::AlreadyExists(error.to_string())
                }
                error => Self::Unknown(error.to_string()),
            },
            // todo: map the rest of the service errors
            error => Self::Unknown(error.to_string()),
        }
    }
}

impl From<ConfigParsingError> for BindingError {
    fn from(error: ConfigParsingError) -> Self {
        Self::ConfigValidationError(error.to_string())
    }
}

impl From<ConfigError> for BindingError {
    fn from(error: ConfigError) -> Self {
        Self::ConfigValidationError(error.to_string())
    }
}

impl From<time::error::Parse> for BindingError {
    fn from(error: time::error::Parse) -> Self {
        Self::ValidationError(format!("OffsetDateTime parse error: {}", error))
    }
}

#[derive(Debug, Error)]
pub enum NativeKeyStorageError {
    #[error("Failed to generate key: {reason:?}")]
    KeyGenerationFailure { reason: String },
    #[error("Failed to crate signature: {reason:?}")]
    SignatureFailure { reason: String },
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
