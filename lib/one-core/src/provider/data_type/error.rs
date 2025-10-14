use thiserror::Error;

use crate::provider::data_type::model::{JsonOrCbor, ValueType};

#[derive(Debug, PartialEq, Error)]
#[allow(dead_code)]
pub enum DataTypeProviderError {
    #[error("Data type provider error: `{0}`")]
    DataTypeError(#[from] DataTypeError),
    #[error("Multiple fallback data types configured for value type: `{value_type}`")]
    MultipleFallbackProviders { value_type: ValueType },
    #[error("Unsupported data type: `{0}`")]
    UnsupportedValue(JsonOrCbor),
    #[error("No provider available to extract data: `{0}`")]
    UnableToExtract(JsonOrCbor),
}

#[derive(Debug, PartialEq, Error)]
#[allow(dead_code)]
pub enum DataTypeError {
    #[error("Failed: `{0}`")]
    Failed(String),
}
