mod boolean;
mod date;
pub mod error;
mod mapper;
pub mod model;
mod number;
pub mod provider;
mod string;

use std::sync::Arc;

use boolean::BooleanDataType;
use date::DateDataType;
use error::DataTypeError;
use model::{
    DataTypeCapabilities, DataTypeProviderInit, ExtractionResult, HolderDataTypeParams,
    ValueExtractionConfig,
};
use number::NumberDataType;
use provider::{DataTypeProvider, DataTypeProviderImpl};
use serde::Deserialize;
use serde_json::json;
use string::StringDataType;

use crate::config::ConfigValidationError;
use crate::config::core_config::{DatatypeConfig, DatatypeType};

#[derive(Debug, Deserialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
struct CommonParams {
    pub holder: Option<HolderDataTypeParams>,
}

pub fn data_type_provider_from_config(
    config: &mut DatatypeConfig,
) -> Result<Arc<dyn DataTypeProvider>, ConfigValidationError> {
    let mut data_type_provider = vec![];
    for (name, fields) in config.iter_mut() {
        let params = fields.deserialize::<CommonParams>().map_err(|source| {
            ConfigValidationError::FieldsDeserialization {
                key: name.to_owned(),
                source,
            }
        })?;
        let Some(holder_config) = &params.holder else {
            continue;
        };
        let fallback = holder_config.value_extraction == ValueExtractionConfig::EnabledFallback;
        let provider: Arc<dyn DataType> = match fields.r#type {
            DatatypeType::String => {
                let params = fields.deserialize::<string::Params>().map_err(|source| {
                    ConfigValidationError::FieldsDeserialization {
                        key: name.to_owned(),
                        source,
                    }
                })?;
                Arc::new(StringDataType::new(params)?)
            }
            DatatypeType::Date => {
                let params = fields.deserialize::<date::Params>().map_err(|source| {
                    ConfigValidationError::FieldsDeserialization {
                        key: name.to_owned(),
                        source,
                    }
                })?;
                Arc::new(DateDataType::new(params)?)
            }
            DatatypeType::Boolean => Arc::new(BooleanDataType),
            DatatypeType::Number => {
                let params = fields.deserialize::<number::Params>().map_err(|source| {
                    ConfigValidationError::FieldsDeserialization {
                        key: name.to_owned(),
                        source,
                    }
                })?;
                Arc::new(NumberDataType::new(params))
            }
            _ => {
                // skip for now, TODO: ONE-7544, ONE-7578
                continue;
            }
        };
        fields.capabilities = Some(json!(provider.get_capabilities()));
        data_type_provider.push(DataTypeProviderInit {
            name: name.to_string(),
            fallback,
            provider,
        });
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
