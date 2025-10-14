use std::collections::HashMap;
use std::sync::Arc;

use crate::provider::data_type::DataType;
use crate::provider::data_type::error::{DataTypeError, DataTypeProviderError};
use crate::provider::data_type::model::{
    DataTypeProviderInit, ExtractedClaim, ExtractionResult, JsonOrCbor, ValueType,
};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[allow(unused)]
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

pub struct DataTypeProviderImpl {
    fallback: HashMap<ValueType, NamedProvider>,
    // regular non-fallback
    data_types: HashMap<String, Arc<dyn DataType>>,
}

impl DataTypeProviderImpl {
    #[expect(dead_code)]
    pub fn new(providers: Vec<DataTypeProviderInit>) -> Result<Self, DataTypeProviderError> {
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
                        return Err(DataTypeProviderError::MultipleFallbackProviders {
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

    #[expect(unused)]
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
