use super::DataType;
use super::error::DataTypeError;
use super::model::{CborType, DataTypeCapabilities, ExtractionResult, JsonType};

pub struct BooleanDataType;

impl DataType for BooleanDataType {
    fn extract_json_claim(
        &self,
        value: &serde_json::Value,
    ) -> Result<ExtractionResult, DataTypeError> {
        Ok(match value {
            serde_json::Value::Bool(value) => ExtractionResult::Value(value.to_string()),
            _ => ExtractionResult::NotApplicable,
        })
    }

    fn extract_cbor_claim(
        &self,
        value: &ciborium::Value,
    ) -> Result<ExtractionResult, DataTypeError> {
        Ok(match value {
            ciborium::Value::Bool(value) => ExtractionResult::Value(value.to_string()),
            _ => ExtractionResult::NotApplicable,
        })
    }

    fn get_capabilities(&self) -> DataTypeCapabilities {
        DataTypeCapabilities {
            supported_json_types: vec![JsonType::Boolean],
            supported_cbor_types: vec![CborType::Bool],
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
        let result = BooleanDataType
            .extract_json_claim(&json!("not matching"))
            .unwrap();
        assert_eq!(result, ExtractionResult::NotApplicable);

        let result = BooleanDataType.extract_json_claim(&json!(true)).unwrap();
        assert_eq!(result, ExtractionResult::Value("true".to_string()));
    }

    #[test]
    fn test_extract_cbor() {
        let result = BooleanDataType
            .extract_cbor_claim(&ciborium::Value::Text("not matching".to_string()))
            .unwrap();
        assert_eq!(result, ExtractionResult::NotApplicable);

        let result = BooleanDataType
            .extract_cbor_claim(&ciborium::Value::Bool(true))
            .unwrap();
        assert_eq!(result, ExtractionResult::Value("true".to_string()));
    }
}
