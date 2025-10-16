use serde::Deserialize;

use crate::provider::data_type::DataType;
use crate::provider::data_type::error::DataTypeError;
use crate::provider::data_type::model::{
    CborType, DataTypeCapabilities, ExtractionResult, JsonType,
};

#[derive(Debug, Deserialize, Clone, Eq, PartialEq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct Params {}

pub struct StringDataType {
    #[expect(unused)]
    pub params: Params,
}

impl StringDataType {
    pub fn new(params: Params) -> Self {
        Self { params }
    }
}

impl DataType for StringDataType {
    fn extract_json_claim(
        &self,
        value: &serde_json::Value,
    ) -> Result<ExtractionResult, DataTypeError> {
        match value {
            serde_json::Value::String(value) => Ok(ExtractionResult::Value(value.clone())),
            _ => Ok(ExtractionResult::NotApplicable),
        }
    }

    fn extract_cbor_claim(
        &self,
        value: &ciborium::Value,
    ) -> Result<ExtractionResult, DataTypeError> {
        match value {
            ciborium::Value::Text(value) => Ok(ExtractionResult::Value(value.clone())),
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
