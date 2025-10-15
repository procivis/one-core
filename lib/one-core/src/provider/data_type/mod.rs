pub mod error;
mod mapper;
pub mod model;
pub mod provider;
mod string;

use std::sync::Arc;

use serde_json::json;

use crate::config::ConfigValidationError;
use crate::config::core_config::{DatatypeConfig, DatatypeType};
use crate::provider::data_type::error::DataTypeError;
use crate::provider::data_type::model::{
    DataTypeCapabilities, DataTypeProviderInit, ExtractionResult, ValueExtractionConfig,
};
use crate::provider::data_type::provider::{DataTypeProvider, DataTypeProviderImpl};
use crate::provider::data_type::string::StringDataType;

pub fn data_type_provider_from_config(
    config: &mut DatatypeConfig,
) -> Result<Arc<dyn DataTypeProvider>, ConfigValidationError> {
    let mut data_type_provider = vec![];
    for (name, fields) in config.iter_mut() {
        match fields.r#type {
            DatatypeType::String => {
                let params = fields.deserialize::<string::Params>().map_err(|source| {
                    ConfigValidationError::FieldsDeserialization {
                        key: name.to_owned(),
                        source,
                    }
                })?;
                let Some(holder_config) = &params.holder else {
                    continue;
                };
                let fallback =
                    holder_config.value_extraction == ValueExtractionConfig::EnabledFallback;
                let provider = Arc::new(StringDataType::new(params));
                fields.capabilities = Some(json!(provider.get_capabilities()));
                data_type_provider.push(DataTypeProviderInit {
                    name: name.to_string(),
                    fallback,
                    provider,
                });
            }
            _ => {
                // skip for now, TODO: ONE-7544, ONE-7578
            }
        }
    }
    Ok(Arc::new(DataTypeProviderImpl::new(data_type_provider)?))
}

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
