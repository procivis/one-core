use std::collections::HashMap;

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct IssuerResponseDTO {
    pub credential: String,
    pub format: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct JsonLDContextResponseDTO {
    pub context: JsonLDContextDTO,
}

#[derive(Clone, Debug, PartialEq)]
pub struct JsonLDContextDTO {
    pub version: f64,
    pub protected: bool,
    pub id: String,
    pub r#type: String,
    pub entities: HashMap<String, JsonLDEntityDTO>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum JsonLDEntityDTO {
    Reference(String),
    Inline(JsonLDInlineEntityDTO),
    NestedObject(JsonLDNestedEntityDTO),
    // TODO: nested claims (ONE-1317)
}
#[derive(Clone, Debug, PartialEq)]
pub struct JsonLDNestedEntityDTO {
    pub id: String,
    pub context: JsonLDNestedContextDTO,
}

#[derive(Clone, Debug, PartialEq)]
pub struct JsonLDNestedContextDTO {
    pub entities: HashMap<String, JsonLDEntityDTO>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct JsonLDInlineEntityDTO {
    pub id: String,
    pub context: JsonLDContextDTO,
}
