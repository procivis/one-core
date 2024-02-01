use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct IssuerResponseDTO {
    pub credential: String,
    pub format: String,
}

#[derive(Clone, Debug)]
pub struct JsonLDContextResponseDTO {
    pub context: JsonLDContextDTO,
}

#[derive(Clone, Debug)]
pub struct JsonLDContextDTO {
    pub version: f64,
    pub protected: bool,
    pub id: String,
    pub r#type: String,
    pub entities: HashMap<String, JsonLDEntityDTO>,
}

#[derive(Clone, Debug)]
pub enum JsonLDEntityDTO {
    Reference(String),
    Inline(JsonLDInlineEntityDTO),
    // TODO: nested claims (ONE-1317)
}

#[derive(Clone, Debug)]
pub struct JsonLDInlineEntityDTO {
    pub id: String,
    pub context: JsonLDContextDTO,
}
