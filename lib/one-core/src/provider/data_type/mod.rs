use error::DataTypeError;
use model::{DataTypeCapabilities, ExtractionResult, HolderDataTypeParams};
use serde::Deserialize;

mod boolean;
mod date;
pub mod error;
mod mapper;
pub mod model;
mod number;
mod picture;
mod picture_utils;
pub mod provider;
mod string;
mod swiyu_picture;

#[derive(Debug, Deserialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
struct CommonParams {
    pub holder: Option<HolderDataTypeParams>,
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait DataType: Send + Sync {
    /// Provider attempts to parse the value and determine its data type.
    /// If the provider finds the value does not match its implemented type,
    /// it will return `DataMismatch`.
    fn extract_json_claim(
        &self,
        value: &serde_json::Value,
    ) -> Result<ExtractionResult, DataTypeError>;

    /// Provider attempts to parse the value and determine its data type.
    /// If the provider finds the value does not match its implemented type,
    /// it will return `DataMismatch`.
    fn extract_cbor_claim(
        &self,
        value: &ciborium::Value,
    ) -> Result<ExtractionResult, DataTypeError>;

    fn get_capabilities(&self) -> DataTypeCapabilities;
}
