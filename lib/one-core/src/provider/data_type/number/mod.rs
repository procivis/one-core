use serde::Deserialize;

use super::DataType;
use super::error::DataTypeError;
use super::model::{CborType, DataTypeCapabilities, ExtractionResult, JsonType};

#[derive(Debug, Deserialize, Clone)]
pub struct Params {
    pub min: Option<f64>,
    pub max: Option<f64>,
}

pub struct NumberDataType {
    params: Params,
}

impl NumberDataType {
    pub fn new(params: Params) -> Self {
        Self { params }
    }

    fn is_valid(&self, value: Option<f64>) -> bool {
        if let Some(min) = &self.params.min
            && value.is_none_or(|value| value < *min)
        {
            return false;
        }
        if let Some(max) = &self.params.max
            && value.is_none_or(|value| value > *max)
        {
            return false;
        }
        true
    }
}

impl DataType for NumberDataType {
    fn extract_json_claim(
        &self,
        value: &serde_json::Value,
    ) -> Result<ExtractionResult, DataTypeError> {
        Ok(match value {
            serde_json::Value::Number(value) if self.is_valid(value.as_f64()) => {
                ExtractionResult::Value(value.to_string())
            }
            _ => ExtractionResult::NotApplicable,
        })
    }

    fn extract_cbor_claim(
        &self,
        value: &ciborium::Value,
    ) -> Result<ExtractionResult, DataTypeError> {
        Ok(match value {
            ciborium::Value::Integer(val) if self.is_valid(Some(i128::from(*val) as _)) => {
                ExtractionResult::Value(i128::from(*val).to_string())
            }
            ciborium::Value::Float(val) if self.is_valid(Some(*val)) => {
                ExtractionResult::Value(val.to_string())
            }
            _ => ExtractionResult::NotApplicable,
        })
    }

    fn get_capabilities(&self) -> DataTypeCapabilities {
        DataTypeCapabilities {
            supported_json_types: vec![JsonType::Number],
            supported_cbor_types: vec![CborType::Integer, CborType::Float],
        }
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use similar_asserts::assert_eq;

    use super::*;

    #[test]
    fn test_extract_json() {
        let provider = NumberDataType::new(Params {
            min: Some(0.0),
            max: None,
        });

        let result = provider.extract_json_claim(&json!(-1)).unwrap();
        assert_eq!(result, ExtractionResult::NotApplicable);

        let result = provider.extract_json_claim(&json!(2)).unwrap();
        assert_eq!(result, ExtractionResult::Value("2".to_string()));
    }

    #[test]
    fn test_extract_cbor() {
        let provider = NumberDataType::new(Params {
            min: Some(0.0),
            max: None,
        });

        assert_eq!(
            provider
                .extract_cbor_claim(&ciborium::Value::Integer((-1).into()))
                .unwrap(),
            ExtractionResult::NotApplicable
        );

        assert_eq!(
            provider
                .extract_cbor_claim(&ciborium::Value::Integer(1.into()))
                .unwrap(),
            ExtractionResult::Value("1".to_string())
        );

        assert_eq!(
            provider
                .extract_cbor_claim(&ciborium::Value::Float(0.1))
                .unwrap(),
            ExtractionResult::Value("0.1".to_string())
        );
    }
}
