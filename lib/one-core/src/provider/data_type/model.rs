use std::sync::Arc;

use serde::{Deserialize, Serialize};
use strum::Display;

use crate::provider::data_type::DataType;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ExtractionResult {
    /// The provider has successfully extracted a value.
    Value(String),
    /// The provider was not able to extract a claim from the provided data. A different provider should be used.
    NotApplicable,
}

/// Extracted claim value from a credential.
pub struct ExtractedClaim {
    /// Name of the data type provider
    pub data_type: String,
    /// Extracted data model value
    pub value: String,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DataTypeCapabilities {
    pub supported_json_types: Vec<JsonType>,
    pub supported_cbor_types: Vec<CborType>,
}

#[derive(Debug, Display, Clone, PartialEq)]
pub enum JsonOrCbor {
    Json(serde_json::Value),
    Cbor(ciborium::Value),
}

#[derive(Debug, Display, Hash, Clone, Copy, Eq, PartialEq)]
pub enum ValueType {
    Json(JsonType),
    Cbor(CborType),
}

#[derive(Debug, Display, Serialize, Deserialize, Clone, Copy, Eq, PartialEq, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum JsonType {
    String,
    Number,
    Boolean,
}

#[derive(Debug, Display, Serialize, Deserialize, Clone, Copy, Eq, PartialEq, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CborType {
    Text,
    Bool,
    Integer,
    Float,
    TDate,
    FullDate,
    Bytes,
    Array, // required for images
}

pub struct DataTypeProviderInit {
    pub name: String,
    pub fallback: bool,
    pub provider: Arc<dyn DataType>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct HolderDataTypeParams {
    pub value_extraction: ValueExtractionConfig,
}

#[derive(Debug, Display, Serialize, Deserialize, Clone, Copy, Eq, PartialEq, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValueExtractionConfig {
    Enabled,
    Disabled,
    EnabledFallback,
}
