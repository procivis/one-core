use std::collections::HashMap;
use std::sync::Arc;

use serde_json::json;

use super::boolean::BooleanDataType;
use super::date::DateDataType;
use super::error::{DataTypeError, DataTypeProviderError};
use super::model::{
    DataTypeProviderInit, ExtractedClaim, ExtractionResult, JsonOrCbor, ValueExtractionConfig,
    ValueType,
};
use super::number::NumberDataType;
use super::picture::PictureDataType;
use super::string::StringDataType;
use super::swiyu_picture::SwiyuPictureDataType;
use super::{CommonParams, DataType, date, number, picture, string, swiyu_picture};
use crate::config::ConfigValidationError;
use crate::config::core_config::{CoreConfig, DatatypeType};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait DataTypeProvider: Send + Sync {
    /// Returns the data type provider with the given name, if any.
    fn get_by_name(&self, provider_name: &str) -> Option<Arc<dyn DataType>>;

    /// Attempts to parse the value and determine its data type. Returns an error if no applicable
    /// provider is available.
    fn extract_json_claim(
        &self,
        value: &serde_json::Value,
    ) -> Result<ExtractedClaim, DataTypeProviderError>;

    /// Attempts to parse the value and determine its data type. Returns an error if no applicable
    /// provider is available.
    fn extract_cbor_claim(
        &self,
        value: &ciborium::Value,
    ) -> Result<ExtractedClaim, DataTypeProviderError>;
}

#[derive(Clone)]
struct NamedProvider {
    name: String,
    provider: Arc<dyn DataType>,
}

struct DataTypeProviderImpl {
    fallback: HashMap<ValueType, NamedProvider>,
    // regular non-fallback
    data_types: HashMap<String, Arc<dyn DataType>>,
}

impl DataTypeProviderImpl {
    fn new(providers: Vec<DataTypeProviderInit>) -> Result<Self, ConfigValidationError> {
        let mut fallback = HashMap::new();
        let mut data_types = HashMap::new();

        for DataTypeProviderInit {
            name,
            fallback: is_fallback,
            provider,
        } in providers
        {
            if is_fallback {
                let capabilities = provider.get_capabilities();
                for value_type in capabilities
                    .supported_json_types
                    .iter()
                    .map(|t| ValueType::Json(*t))
                    .chain(
                        capabilities
                            .supported_cbor_types
                            .iter()
                            .map(|t| ValueType::Cbor(*t)),
                    )
                {
                    let existing = fallback.insert(
                        value_type,
                        NamedProvider {
                            name: name.clone(),
                            provider: provider.clone(),
                        },
                    );
                    if existing.is_some() {
                        return Err(ConfigValidationError::MultipleFallbackProviders {
                            value_type,
                        });
                    }
                }
            } else {
                data_types.insert(name, provider);
            }
        }

        Ok(Self {
            fallback,
            data_types,
        })
    }

    fn get_by_value_type(&self, value_type: ValueType) -> Vec<NamedProvider> {
        let mut result = vec![];
        for (name, provider) in &self.data_types {
            match value_type {
                ValueType::Json(r#type) => {
                    if provider
                        .get_capabilities()
                        .supported_json_types
                        .contains(&r#type)
                    {
                        result.push(NamedProvider {
                            name: name.clone(),
                            provider: provider.clone(),
                        });
                    }
                }
                ValueType::Cbor(r#type) => {
                    if provider
                        .get_capabilities()
                        .supported_cbor_types
                        .contains(&r#type)
                    {
                        result.push(NamedProvider {
                            name: name.clone(),
                            provider: provider.clone(),
                        });
                    }
                }
            }
        }
        if let Some(fallback) = self.fallback.get(&value_type) {
            result.push(fallback.clone());
        }
        result
    }

    fn extract_claim<'a, T>(
        &self,
        value: &'a T,
        extract: &dyn Fn(&dyn DataType, &'a T) -> Result<ExtractionResult, DataTypeError>,
    ) -> Result<ExtractedClaim, DataTypeProviderError>
    where
        T: Clone + Into<JsonOrCbor>,
        &'a T: TryInto<ValueType, Error = DataTypeProviderError>,
    {
        let providers = self.get_by_value_type(value.try_into()?);
        for NamedProvider { name, provider } in providers {
            let result = extract(&*provider, value)?;
            match result {
                ExtractionResult::Value(value) => {
                    return Ok(ExtractedClaim {
                        data_type: name,
                        value,
                    });
                }
                ExtractionResult::NotApplicable => {}
            }
        }
        Err(DataTypeProviderError::UnableToExtract(value.clone().into()))
    }
}

impl DataTypeProvider for DataTypeProviderImpl {
    fn get_by_name(&self, provider_name: &str) -> Option<Arc<dyn DataType>> {
        self.data_types.get(provider_name).cloned().or_else(|| {
            self.fallback.iter().find_map(|(_, p)| {
                if p.name == provider_name {
                    Some(p.provider.clone())
                } else {
                    None
                }
            })
        })
    }

    fn extract_json_claim(
        &self,
        value: &serde_json::Value,
    ) -> Result<ExtractedClaim, DataTypeProviderError> {
        self.extract_claim(value, &|provider: &dyn DataType, value| {
            provider.extract_json_claim(value)
        })
    }

    fn extract_cbor_claim(
        &self,
        value: &ciborium::Value,
    ) -> Result<ExtractedClaim, DataTypeProviderError> {
        self.extract_claim(value, &|provider: &dyn DataType, value| {
            provider.extract_cbor_claim(value)
        })
    }
}

pub(crate) fn data_type_provider_from_config(
    config: &mut CoreConfig,
) -> Result<Arc<dyn DataTypeProvider>, ConfigValidationError> {
    let mut data_type_provider = vec![];
    for (name, fields) in config.datatype.iter_mut() {
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
            DatatypeType::Picture => {
                let params = fields.deserialize::<picture::Params>().map_err(|source| {
                    ConfigValidationError::FieldsDeserialization {
                        key: name.to_owned(),
                        source,
                    }
                })?;
                Arc::new(PictureDataType::new(params))
            }
            DatatypeType::SwiyuPicture => {
                let params = fields
                    .deserialize::<swiyu_picture::Params>()
                    .map_err(|source| ConfigValidationError::FieldsDeserialization {
                        key: name.to_owned(),
                        source,
                    })?;
                Arc::new(SwiyuPictureDataType::new(params)?)
            }
            DatatypeType::Array | DatatypeType::Object => {
                // skip Array and Objects until we support data extraction for intermediary claims
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
