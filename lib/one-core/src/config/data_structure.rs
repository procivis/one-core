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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoreConfig {
    pub format: HashMap<String, FormatEntity>,
    pub exchange: HashMap<String, ExchangeEntity>,
    pub transport: HashMap<String, TransportEntity>,
    pub revocation: HashMap<String, RevocationEntity>,
    pub did: HashMap<String, DidEntity>,
    pub datatype: HashMap<String, DatatypeEntity>,
    pub key_storage: HashMap<String, KeyStorageEntity>,
}

pub type FormatEntity = ConfigEntity<String, serde_json::Value>;
pub type ExchangeEntity = ConfigEntity<String, serde_json::Value>;
pub type TransportEntity = ConfigEntity<String, serde_json::Value>;
pub type RevocationEntity = ConfigEntity<String, serde_json::Value>;
pub type DidEntity = ConfigEntity<DidType, DidParams>;
pub type DatatypeEntity = ConfigEntity<DatatypeType, DatatypeParams>;
pub type KeyStorageEntity = ConfigEntity<String, KeyStorageParams>;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DidType {
    Key,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DatatypeType {
    String,
    Number,
    Date,
    Enum,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConfigEntity<TypeEnum, ParamsType> {
    pub r#type: TypeEnum,
    pub display: TranslatableString,
    pub order: Option<u32>,
    pub params: Option<ParamsEnum<ParamsType>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TranslatableString {
    Key(String),
    Map(HashMap<String, String>),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ParamsEnum<ParamsType> {
    Unparsed(serde_json::Value),
    Parsed(ParamsType),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Param<ParamType> {
    pub access: AccessModifier,
    pub value: ParamType,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum AccessModifier {
    Public,
    Private,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum DidParams {
    Key(DidKeyParams),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DidKeyParams {}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum DatatypeParams {
    String(DatatypeStringParams),
    Number(DatatypeNumberParams),
    Date(DatatypeDateParams),
    Enum(DatatypeEnumParams),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DatatypeStringParams {
    pub autocomplete: Option<Param<bool>>,
    pub placeholder: Option<Param<String>>,
    pub error: Option<Param<TranslatableString>>,
    pub pattern: Option<Param<String>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DatatypeNumberParams {
    pub min: Option<Param<f64>>,
    pub max: Option<Param<f64>>,
    pub error: Option<Param<TranslatableString>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DatatypeDateParams {
    pub min: Option<Param<String>>,
    pub max: Option<Param<String>>,
    pub error: Option<Param<TranslatableString>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DatatypeEnumParams {
    pub values: Option<Param<Vec<EnumValue>>>,
    pub error: Option<Param<TranslatableString>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EnumValue {
    pub key: String,
    pub value: Option<String>,
    pub display: Option<TranslatableString>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum KeyStorageParams {
    Internal(KeyStorageInternalParams),
    HsmAzure(KeyStorageHsmAzureParams),
    Unknown(serde_json::Value),
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct KeyStorageInternalParams {
    pub encryption: Option<Param<String>>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyStorageHsmAzureParams {
    pub instance_url: Option<Param<String>>,
    pub account: Option<Param<String>>,
    pub access_token: Option<Param<String>>,
}
