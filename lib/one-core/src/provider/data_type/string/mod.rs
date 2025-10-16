use regex::Regex;
use serde::Deserialize;

use crate::config::ConfigValidationError;
use crate::config::validator::datatype::DatatypeValidationError;
use crate::provider::data_type::DataType;
use crate::provider::data_type::error::DataTypeError;
use crate::provider::data_type::model::{
    CborType, DataTypeCapabilities, ExtractionResult, JsonType,
};

#[derive(Debug, Deserialize, Clone, Eq, PartialEq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    pattern: Option<String>,
}

pub struct StringDataType {
    pub matcher: Option<Regex>,
}

impl StringDataType {
    pub fn new(params: Params) -> Result<Self, ConfigValidationError> {
        let matcher = params
            .pattern
            .map(|p| Regex::new(&p))
            .transpose()
            .map_err(DatatypeValidationError::StringInvalidPattern)?;
        Ok(Self { matcher })
    }

    fn is_valid(&self, value: &str) -> bool {
        match &self.matcher {
            Some(re) => re.is_match_at(value, 0),
            None => true,
        }
    }
}

impl DataType for StringDataType {
    fn extract_json_claim(
        &self,
        value: &serde_json::Value,
    ) -> Result<ExtractionResult, DataTypeError> {
        match value {
            serde_json::Value::String(value) if self.is_valid(value) => {
                Ok(ExtractionResult::Value(value.clone()))
            }
            _ => Ok(ExtractionResult::NotApplicable),
        }
    }

    fn extract_cbor_claim(
        &self,
        value: &ciborium::Value,
    ) -> Result<ExtractionResult, DataTypeError> {
        match value {
            ciborium::Value::Text(value) if self.is_valid(value) => {
                Ok(ExtractionResult::Value(value.clone()))
            }
            _ => Ok(ExtractionResult::NotApplicable),
        }
    }

    fn get_capabilities(&self) -> DataTypeCapabilities {
        DataTypeCapabilities {
            supported_json_types: vec![JsonType::String],
            supported_cbor_types: vec![CborType::Text],
        }
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use similar_asserts::assert_eq;

    use super::*;

    #[test]
    fn extract_with_pattern_json() {
        let email_pattern = r#"^[\w\-\.]+@([\w\-]+\.)+[\w\-]{2,4}$"#;
        let provider = StringDataType::new(Params {
            pattern: Some(email_pattern.to_owned()),
        })
        .unwrap();

        let result = provider.extract_json_claim(&json!("not matching")).unwrap();
        assert_eq!(result, ExtractionResult::NotApplicable);

        let result = provider
            .extract_json_claim(&json!("user@match.com"))
            .unwrap();
        assert_eq!(
            result,
            ExtractionResult::Value("user@match.com".to_string())
        );
    }

    #[test]
    fn extract_with_pattern_cbor() {
        let email_pattern = r#"^[\w\-\.]+@([\w\-]+\.)+[\w\-]{2,4}$"#;
        let provider = StringDataType::new(Params {
            pattern: Some(email_pattern.to_owned()),
        })
        .unwrap();

        let result = provider
            .extract_cbor_claim(&ciborium::Value::Text("not matching".to_string()))
            .unwrap();
        assert_eq!(result, ExtractionResult::NotApplicable);

        let result = provider
            .extract_cbor_claim(&ciborium::Value::Text("user@match.com".to_string()))
            .unwrap();
        assert_eq!(
            result,
            ExtractionResult::Value("user@match.com".to_string())
        );
    }
}
