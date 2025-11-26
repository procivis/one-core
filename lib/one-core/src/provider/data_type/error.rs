use thiserror::Error;

use crate::provider::data_type::model::JsonOrCbor;

#[derive(Debug, PartialEq, Error)]
pub enum DataTypeProviderError {
    #[error("Data type provider error: `{0}`")]
    DataTypeError(#[from] DataTypeError),
    #[error("Unsupported data type: `{0}`")]
    UnsupportedValue(JsonOrCbor),
    #[error("No provider available to extract data: `{0}`")]
    UnableToExtract(JsonOrCbor),
}

#[derive(Debug, PartialEq, Error)]
pub enum DataTypeError {
    #[error("Failed: `{0}`")]
    Failed(String),
}
