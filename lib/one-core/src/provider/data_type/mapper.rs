use crate::provider::data_type::error::DataTypeProviderError;
use crate::provider::data_type::model::{CborType, JsonOrCbor, JsonType, ValueType};

impl TryFrom<&serde_json::Value> for ValueType {
    type Error = DataTypeProviderError;

    fn try_from(value: &serde_json::Value) -> Result<Self, Self::Error> {
        Ok(match value {
            serde_json::Value::String(_) => ValueType::Json(JsonType::String),
            serde_json::Value::Bool(_) => ValueType::Json(JsonType::Boolean),
            serde_json::Value::Number(_) => ValueType::Json(JsonType::Number),
            val => {
                return Err(DataTypeProviderError::UnsupportedValue(val.clone().into()));
            }
        })
    }
}

const FULL_DATE_TAG: u64 = 1004;
const TDATE_TAG: u64 = 0;

impl TryFrom<&ciborium::Value> for ValueType {
    type Error = DataTypeProviderError;

    fn try_from(value: &ciborium::Value) -> Result<Self, Self::Error> {
        Ok(match value {
            ciborium::Value::Text(_) => ValueType::Cbor(CborType::Text),
            ciborium::Value::Bool(_) => ValueType::Cbor(CborType::Bool),
            ciborium::Value::Integer(_) => ValueType::Cbor(CborType::Integer),
            ciborium::Value::Float(_) => ValueType::Cbor(CborType::Float),
            ciborium::Value::Bytes(_) => ValueType::Cbor(CborType::Bytes),
            ciborium::Value::Array(_) => ValueType::Cbor(CborType::Array),
            ciborium::Value::Tag(TDATE_TAG, _) => ValueType::Cbor(CborType::TDate),
            ciborium::Value::Tag(FULL_DATE_TAG, _) => ValueType::Cbor(CborType::FullDate),
            val => {
                return Err(DataTypeProviderError::UnsupportedValue(val.clone().into()));
            }
        })
    }
}

impl From<serde_json::Value> for JsonOrCbor {
    fn from(value: serde_json::Value) -> Self {
        Self::Json(value)
    }
}

impl From<ciborium::Value> for JsonOrCbor {
    fn from(value: ciborium::Value) -> Self {
        Self::Cbor(value)
    }
}
