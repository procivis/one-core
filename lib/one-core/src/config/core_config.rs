use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
};

use figment::{providers::Format, Figment};

#[cfg(feature = "config_env")]
use figment::providers::Env;

#[cfg(feature = "config_yaml")]
use figment::providers::Yaml;

#[cfg(feature = "config_json")]
use figment::providers::Json;

use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};
use serde_with::{serde_as, DurationSeconds};
use strum_macros::{Display, EnumString};

use super::{ConfigParsingError, ConfigValidationError};

type Dict<K, V> = BTreeMap<K, V>;

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct NoCustomConfig;

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppConfig<Custom> {
    #[serde(flatten)]
    pub core: CoreConfig,
    #[serde(default)]
    pub app: Custom,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoreConfig {
    pub(crate) format: FormatConfig,
    pub(crate) exchange: ExchangeConfig,
    pub(crate) revocation: RevocationConfig,
    pub(crate) did: DidConfig,
    pub(crate) datatype: DatatypeConfig,
    pub(crate) key_algorithm: KeyAlgorithmConfig,
    pub(crate) key_storage: KeyStorageConfig,
    pub(crate) task: TaskConfig,
    pub(crate) trust_management: TrustManagementConfig,
}

#[serde_as]
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonLdContextConfig {
    #[serde_as(as = "DurationSeconds<i64>")]
    pub cache_refresh_timeout: time::Duration,
    pub cache_size: u32,
}

#[derive(Debug)]
pub(super) enum InputFormat {
    #[cfg(feature = "config_yaml")]
    Yaml { content: String },
    #[cfg(feature = "config_json")]
    Json { content: String },
}

impl<Custom> AppConfig<Custom>
where
    Custom: Serialize + DeserializeOwned + Default,
{
    pub fn from_files(files: &[impl AsRef<std::path::Path>]) -> Result<Self, ConfigParsingError> {
        let mut inputs: Vec<InputFormat> = Vec::with_capacity(files.len());

        for path in files {
            let file_content =
                std::fs::read_to_string(path.as_ref()).map_err(ConfigParsingError::File)?;

            #[cfg(feature = "config_yaml")]
            if path
                .as_ref()
                .extension()
                .is_some_and(|ext| ext == "yml" || ext == "yaml")
            {
                inputs.push(InputFormat::Yaml {
                    content: file_content,
                });
                continue;
            }

            #[cfg(feature = "config_json")]
            if path.as_ref().extension() == Some("json".as_ref()) {
                inputs.push(InputFormat::Json {
                    content: file_content,
                });
                continue;
            }

            return Err(ConfigParsingError::GeneralParsingError(format!(
                "Unsupported file or missing file extension: {:?}",
                path.as_ref().to_str()
            )));
        }

        AppConfig::parse(inputs)
    }

    pub fn from_yaml_str_configs(
        configs: Vec<impl AsRef<str>>,
    ) -> Result<Self, ConfigParsingError> {
        let inputs = configs
            .into_iter()
            .map(|input| InputFormat::Yaml {
                content: input.as_ref().to_owned(),
            })
            .collect();

        AppConfig::parse(inputs)
    }

    pub(super) fn parse(inputs: Vec<InputFormat>) -> Result<Self, ConfigParsingError> {
        let mut figment = Figment::new();

        for data in inputs {
            figment = match data {
                #[cfg(feature = "config_yaml")]
                InputFormat::Yaml { content } => figment.merge(Yaml::string(&content)),
                #[cfg(feature = "config_json")]
                InputFormat::Json { content } => figment.merge(Json::string(&content)),
            };
        }

        #[cfg(feature = "config_env")]
        {
            figment = figment.merge(Env::prefixed("ONE_").split("__").lowercase(false));
        }

        figment
            .extract()
            .map_err(|e| ConfigParsingError::GeneralParsingError(e.to_string()))
    }
}

pub type FormatConfig = ConfigBlock<FormatType>;

#[derive(
    Debug, Copy, Clone, Display, EnumString, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
pub enum FormatType {
    #[serde(rename = "JWT")]
    #[strum(serialize = "JWT")]
    Jwt,
    #[serde(rename = "SDJWT")]
    #[strum(serialize = "SDJWT")]
    Sdjwt,
    #[serde(rename = "JSON_LD_CLASSIC")]
    #[strum(serialize = "JSON_LD_CLASSIC")]
    JsonLdClassic,
    #[serde(rename = "JSON_LD_BBSPLUS")]
    #[strum(serialize = "JSON_LD_BBSPLUS")]
    JsonLdBbsplus,
    #[serde(rename = "MDOC")]
    #[strum(serialize = "MDOC")]
    Mdoc,
}

pub type ExchangeConfig = ConfigBlock<ExchangeType>;

#[derive(
    Debug, Copy, Clone, Display, EnumString, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
pub enum ExchangeType {
    #[serde(rename = "PROCIVIS_TEMPORARY")]
    #[strum(serialize = "PROCIVIS_TEMPORARY")]
    ProcivisTemporary,
    #[serde(rename = "OPENID4VC")]
    #[strum(serialize = "OPENID4VC")]
    OpenId4Vc,
    #[serde(rename = "MDL")]
    #[strum(serialize = "MDL")]
    Mdl,
}

pub type TransportConfig = ConfigBlock<TransportType>;

#[derive(
    Debug, Copy, Clone, Display, EnumString, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
pub enum TransportType {
    #[serde(rename = "HTTP")]
    Http,
}

pub type RevocationConfig = ConfigBlock<RevocationType>;

#[derive(
    Debug, Copy, Clone, Display, EnumString, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
pub enum RevocationType {
    #[serde(rename = "NONE")]
    #[strum(serialize = "NONE")]
    None,
    #[serde(rename = "LVVC")]
    #[strum(serialize = "LVVC")]
    Lvvc,
    #[serde(rename = "BITSTRINGSTATUSLIST")]
    #[strum(serialize = "BITSTRINGSTATUSLIST")]
    BitstringStatusList,
}

pub type DidConfig = ConfigBlock<DidType>;

#[derive(
    Debug, Copy, Clone, Display, EnumString, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
pub enum DidType {
    #[serde(rename = "KEY")]
    #[strum(serialize = "KEY")]
    Key,
    #[serde(rename = "WEB")]
    #[strum(serialize = "WEB")]
    Web,
    #[serde(rename = "JWK")]
    #[strum(serialize = "JWK")]
    Jwk,
    #[serde(rename = "X509")]
    #[strum(serialize = "X509")]
    X509,
    #[serde(rename = "UNIVERSAL_RESOLVER")]
    #[strum(serialize = "UNIVERSAL_RESOLVER")]
    UNIVERSAL,
    #[serde(rename = "MDL")]
    #[strum(serialize = "MDL")]
    MDL,
}

pub type DatatypeConfig = ConfigBlock<DatatypeType>;

#[derive(
    Debug, Copy, Clone, Display, EnumString, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
pub enum DatatypeType {
    #[serde(rename = "STRING")]
    #[strum(serialize = "STRING")]
    String,
    #[serde(rename = "NUMBER")]
    #[strum(serialize = "NUMBER")]
    Number,
    #[serde(rename = "DATE")]
    #[strum(serialize = "DATE")]
    Date,
    #[serde(rename = "FILE")]
    #[strum(serialize = "FILE")]
    File,
    #[serde(rename = "OBJECT")]
    #[strum(serialize = "OBJECT")]
    Object,
}

pub type KeyAlgorithmConfig = ConfigBlock<KeyAlgorithmType>;

#[derive(
    Debug, Copy, Clone, Display, EnumString, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
pub enum KeyAlgorithmType {
    #[serde(rename = "EDDSA")]
    #[strum(serialize = "EDDSA")]
    Eddsa,
    #[serde(rename = "BBS_PLUS")]
    #[strum(serialize = "BBS_PLUS")]
    BbsPlus,
    #[serde(rename = "ES256")]
    #[strum(serialize = "ES256")]
    Es256,
    // Fixme change to ML_DSA when possible
    #[serde(rename = "DILITHIUM")]
    #[strum(serialize = "DILITHIUM")]
    MlDsa,
}

pub type KeyStorageConfig = ConfigBlock<KeyStorageType>;

#[derive(
    Debug, Copy, Clone, Display, EnumString, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
pub enum KeyStorageType {
    #[serde(rename = "INTERNAL")]
    #[strum(serialize = "INTERNAL")]
    Internal,
    #[serde(rename = "PKCS11")]
    #[strum(serialize = "PKCS11")]
    Pkcs11,
    #[serde(rename = "AZURE_VAULT")]
    #[strum(serialize = "AZURE_VAULT")]
    AzureVault,
    #[serde(rename = "SECURE_ELEMENT")]
    #[strum(serialize = "SECURE_ELEMENT")]
    SecureElement,
}

pub type TaskConfig = ConfigBlock<TaskType>;

#[derive(
    Debug, Copy, Clone, Display, EnumString, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
pub enum TaskType {
    #[serde(rename = "SUSPEND_CHECK")]
    #[strum(serialize = "SUSPEND_CHECK")]
    SuspendCheck,
}

pub type TrustManagementConfig = ConfigBlock<TrustManagementType>;

#[derive(
    Debug, Copy, Clone, Display, EnumString, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
pub enum TrustManagementType {
    #[serde(rename = "SIMPLE_TRUST_LIST")]
    #[strum(serialize = "SIMPLE_TRUST_LIST")]
    SimpleTrustList,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ConfigBlock<T>(Dict<String, Fields<T>>);

impl<T> ConfigBlock<T>
where
    T: Serialize + Clone,
{
    // Deserialize current fields for a given key into a type.
    // Private and public fields will be merged.
    pub fn get<U>(&self, key: &str) -> Result<U, ConfigValidationError>
    where
        U: DeserializeOwned,
    {
        let fields = self
            .0
            .get(key)
            .ok_or_else(|| ConfigValidationError::KeyNotFound(key.to_owned()))?;

        fields
            .deserialize()
            .map_err(|source| ConfigValidationError::FieldsDeserialization {
                key: key.to_owned(),
                source,
            })
    }

    pub fn get_by_type<U>(&self, key: T) -> Result<U, ConfigValidationError>
    where
        U: DeserializeOwned,
        T: PartialEq + std::fmt::Display,
    {
        self.iter()
            .find(|(_, v)| v.r#type == key)
            .ok_or_else(|| ConfigValidationError::TypeNotFound(key.to_string()))?
            .1
            .deserialize()
            .map_err(|source| ConfigValidationError::FieldsDeserialization {
                key: key.to_string(),
                source,
            })
    }

    pub fn get_fields(&self, key: &str) -> Result<&Fields<T>, ConfigValidationError> {
        let fields = self
            .0
            .get(key)
            .ok_or(ConfigValidationError::KeyNotFound(key.to_string()))?;

        Ok(fields)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &Fields<T>)> {
        self.0.iter().map(|(k, v)| (k as _, v))
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&str, &mut Fields<T>)> {
        self.0.iter_mut().map(|(k, v)| (k as _, v))
    }

    pub fn get_if_enabled(&self, key: &str) -> Result<&Fields<T>, ConfigValidationError> {
        let fields = self.get_fields(key)?;

        if fields.disabled() {
            return Err(ConfigValidationError::KeyDisabled(key.to_owned()));
        }

        Ok(fields)
    }

    #[cfg(test)]
    pub fn insert(&mut self, key: String, fields: Fields<T>) {
        self.0.insert(key, fields);
    }
}

impl<T> Default for ConfigBlock<T> {
    fn default() -> Self {
        Self(Dict::default())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Fields<T> {
    pub(crate) r#type: T,
    pub(crate) display: Value,
    pub(crate) order: Option<u64>,
    pub(crate) disabled: Option<bool>,
    #[serde(skip_deserializing, skip_serializing_if = "Option::is_none")]
    pub(crate) capabilities: Option<Value>,
    #[serde(default, deserialize_with = "deserialize_params")]
    pub(crate) params: Option<Params>,
}

impl<T> Fields<T>
where
    T: Serialize + Clone,
{
    pub fn r#type(&self) -> &T {
        &self.r#type
    }

    pub fn disabled(&self) -> bool {
        self.disabled == Some(true)
    }

    /// Deserialize current fields into a type.
    /// Private and public fields will be merged.
    fn deserialize<U: DeserializeOwned>(&self) -> Result<U, serde_json::Error> {
        let options = self.merge_fields();
        serde_json::from_value(options)
    }

    // merge public and private params with other fields
    fn merge_fields(&self) -> Value {
        let mut map = json!(Self {
            params: None,
            ..self.clone()
        });

        if let Some(map) = map.as_object_mut() {
            _ = map.remove("params");

            let iter = self
                .params
                .as_ref()
                .and_then(|p| p.merge())
                .and_then(|v| v.as_object().cloned())
                .into_iter()
                .flatten();
            map.extend(iter)
        }

        map
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    pub(crate) public: Option<Value>,
    pub(crate) private: Option<Value>,
}

impl Params {
    // Merge public and private params.
    // Public params will override private ones if there have the same keys
    fn merge(&self) -> Option<Value> {
        let mut map = serde_json::map::Map::new();

        if let Some(private) = &self.private {
            let iter = private.as_object().cloned().into_iter().flatten();
            map.extend(iter);
        }

        if let Some(public) = &self.public {
            let iter = public.as_object().cloned().into_iter().flatten();
            map.extend(iter);
        }

        if !map.is_empty() {
            Some(map.into())
        } else {
            None
        }
    }
}

// deserialize into a map while checking for overlapping keys
fn deserialize_params<'de, D>(t: D) -> Result<Option<Params>, D::Error>
where
    D: Deserializer<'de>,
{
    let value: Value = Value::deserialize(t)?;

    if let Some(map) = value.as_object() {
        check_overlapping_params(map).map_err(serde::de::Error::custom)?;
    }

    serde_json::from_value(value).map_err(serde::de::Error::custom)
}

fn check_overlapping_params(object: &serde_json::Map<String, Value>) -> Result<(), String> {
    let public = object.get("public").and_then(|v| v.as_object());
    let private = object.get("private").and_then(|v| v.as_object());

    if let Some((public, private)) = public.zip(private) {
        let public_keys = BTreeSet::from_iter(public.keys());
        let private_keys = BTreeSet::from_iter(private.keys());

        let overlapping: Vec<&str> = public_keys
            .intersection(&private_keys)
            .map(|s| s.as_str())
            .collect();

        if !overlapping.is_empty() {
            let keys: Vec<_> = overlapping
                .iter()
                .map(|key| format!("[private.{key}, public.{key}]"))
                .collect();
            let keys = keys.join(", ");

            return Err(format!(
                "Public and private params have overlapping keys: {keys}"
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn test_merge_fields_with_public_and_private_params() {
        let fields = Fields {
            r#type: "JWT".to_string(),
            display: Value::String("jwt".to_string()),
            order: Some(0),
            disabled: None,
            capabilities: None,
            params: Some(Params {
                public: Some(json!({ "leeway": 60 })),
                private: Some(json!({ "other": "thing" })),
            }),
        };

        let merged = fields.merge_fields();

        assert_eq!(
            merged,
            json!({
                "type": "JWT",
                "display": "jwt",
                "order": 0,
                "disabled": null,
                //params
                "leeway": 60,
                "other": "thing"
            })
        );
    }

    #[test]
    fn test_merge_public_and_private_params() {
        let params = Params {
            public: Some(json!({ "leeway": 60 })),
            private: Some(json!({
                "other": "thing",
                "error": {
                    "en": "description"
                }
            })),
        };

        let merged = params.merge();

        assert_eq!(
            merged.unwrap(),
            json!({
                "leeway": 60,
                "other": "thing",
                "error": {
                    "en": "description"
                }
            })
        );
    }

    #[test]
    fn test_return_error_when_public_and_private_keys_overlap() {
        let partial_config = indoc::indoc! {"
                    display: 'display'
                    type: 'TYPE'
                    order: 200
                    params:
                        public:
                            min: 10.0
                        private:
                            min: 2.0
        "};

        let err = serde_yaml::from_str::<Fields<String>>(partial_config)
            .err()
            .unwrap();

        assert_eq!(
            "Public and private params have overlapping keys: [private.min, public.min]",
            err.to_string()
        );
    }
}
