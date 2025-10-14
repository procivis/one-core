mod error;
mod mapper;
mod model;
mod provider;

use crate::provider::data_type::error::DataTypeError;
use crate::provider::data_type::model::{DataTypeCapabilities, ExtractionResult};

#[allow(clippy::too_many_arguments)]
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
