use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::provider::data_type::model::JsonOrCbor;

#[derive(Debug, Error)]
pub enum DataTypeProviderError {
    #[error("Unsupported data type: `{0}`")]
    UnsupportedValue(JsonOrCbor),
    #[error("No provider available to extract data: `{0}`")]
    UnableToExtract(JsonOrCbor),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for DataTypeProviderError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::UnsupportedValue(_) | Self::UnableToExtract(_) => ErrorCode::BR_0061,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}

#[derive(Debug, Error)]
pub enum DataTypeError {
    #[error("Unexpected value: `{0}`")]
    UnexpectedValue(String),

    #[error("Encoding error: `{0}`")]
    EncodingError(#[from] ct_codecs::Error),
}

impl ErrorCodeMixin for DataTypeError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::EncodingError(_) => ErrorCode::BR_0000,
            Self::UnexpectedValue(_) => ErrorCode::BR_0061,
        }
    }
}
