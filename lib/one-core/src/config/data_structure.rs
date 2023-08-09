use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub struct UnparsedConfig {
    pub content: String,
    pub kind: ConfigKind,
}

pub enum ConfigKind {
    Json,
    Yaml,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CoreConfig {
    pub format: HashMap<String, FormatEntity>,
    pub exchange: HashMap<String, ExchangeEntity>,
    pub did: HashMap<String, DidEntity>,
    pub datatype: HashMap<String, DatatypeEntity>,
}

pub type FormatEntity = ConfigEntity<String, serde_json::Value>;
pub type ExchangeEntity = ConfigEntity<String, serde_json::Value>;
pub type DidEntity = ConfigEntity<DidType, DidParams>;
pub type DatatypeEntity = ConfigEntity<DatatypeType, DatatypeParams>;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DidType {
    Key,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DatatypeType {
    String,
    Number,
    Date,
    Enum,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ConfigEntity<TypeEnum, ParamsType> {
    pub r#type: TypeEnum,
    pub display: TranslatableString,
    pub order: Option<u32>,
    pub params: Option<ParamsEnum<ParamsType>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum TranslatableString {
    Value(String),
    Map(HashMap<String, String>),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum ParamsEnum<ParamsType> {
    Unparsed(serde_json::Value),
    Parsed(ParamsType),
}

#[derive(Clone, Debug, Deserialize)]
pub struct Params<ParamsType> {
    pub public: Option<ParamsType>,
    pub private: Option<ParamsType>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Param<ParamType> {
    pub access: AccessModifier,
    pub value: ParamType,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum AccessModifier {
    Public,
    Private,
}

#[derive(Clone, Debug, Deserialize)]
pub enum DidParams {
    Key(DidKeyParams),
}

#[derive(Clone, Debug, Deserialize)]
pub struct DidKeyParams {}

#[derive(Clone, Debug, Deserialize)]
pub enum DatatypeParams {
    String(DatatypeStringParams),
    Number(DatatypeNumberParams),
    Date(DatatypeDateParams),
    Enum(DatatypeEnumParams),
}

#[derive(Clone, Debug, Deserialize)]
pub struct DatatypeStringParams {
    pub autocomplete: Option<Param<bool>>,
    pub placeholder: Option<Param<String>>,
    pub error: Option<Param<TranslatableString>>,
    pub pattern: Option<Param<String>>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DatatypeNumberParams {
    pub min: Option<Param<f64>>,
    pub max: Option<Param<f64>>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DatatypeDateParams {
    pub min: Option<Param<String>>,
    pub max: Option<Param<String>>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DatatypeEnumParams {
    pub values: Option<Param<Vec<EnumValue>>>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct EnumValue {
    pub key: String,
    pub value: Option<String>,
    pub display: Option<TranslatableString>,
}
