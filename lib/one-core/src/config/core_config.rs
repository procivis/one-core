use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Debug;

#[cfg(feature = "config_env")]
use figment::providers::Env;
use figment::providers::Format;
#[cfg(feature = "config_json")]
use figment::providers::Json;
#[cfg(feature = "config_yaml")]
use figment::providers::Yaml;
use figment::Figment;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};
use serde_with::{serde_as, skip_serializing_none, DurationSeconds};
use strum::{AsRefStr, Display, EnumString};

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
    pub(crate) transport: TransportConfig,
    pub(crate) revocation: RevocationConfig,
    pub(crate) did: DidConfig,
    pub(crate) datatype: DatatypeConfig,
    pub(crate) key_algorithm: KeyAlgorithmConfig,
    pub(crate) key_storage: KeyStorageConfig,
    pub(crate) task: TaskConfig,
    pub(crate) trust_management: TrustManagementConfig,
    pub cache_entities: CacheEntitiesConfig,
}

impl CoreConfig {
    pub fn get_datatypes_of_type(&self, datatype: DatatypeType) -> Vec<&str> {
        self.datatype
            .iter()
            .filter_map(|(key, fields)| {
                if fields.r#type == datatype {
                    Some(key)
                } else {
                    None
                }
            })
            .collect::<Vec<&str>>()
    }
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheEntitiesConfig {
    #[serde(flatten)]
    pub entities: HashMap<String, CacheEntityConfig>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CacheEntityCacheType {
    Db,
    #[default]
    InMemory,
}

#[serde_as]
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheEntityConfig {
    #[serde_as(as = "DurationSeconds<i64>")]
    pub cache_refresh_timeout: time::Duration,
    pub cache_size: u32,
    pub cache_type: CacheEntityCacheType,
    #[serde_as(as = "DurationSeconds<i64>")]
    pub refresh_after: time::Duration,
}

#[derive(Debug)]
pub enum InputFormat {
    #[cfg(feature = "config_yaml")]
    Yaml(String),
    #[cfg(feature = "config_json")]
    Json(String),
}

impl InputFormat {
    pub fn yaml(s: impl Into<String>) -> Self {
        Self::Yaml(s.into())
    }

    #[cfg(feature = "config_json")]
    pub fn json(s: impl Into<String>) -> Self {
        Self::Json(s.into())
    }
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
                inputs.push(InputFormat::Yaml(file_content));
                continue;
            }

            #[cfg(feature = "config_json")]
            if path.as_ref().extension() == Some("json".as_ref()) {
                inputs.push(InputFormat::Json(file_content));
                continue;
            }

            return Err(ConfigParsingError::GeneralParsingError(format!(
                "Unsupported file or missing file extension: {:?}",
                path.as_ref().to_str()
            )));
        }

        AppConfig::parse(inputs)
    }

    pub fn from_yaml(
        configs: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, ConfigParsingError> {
        let inputs = configs.into_iter().map(InputFormat::yaml);

        AppConfig::parse(inputs)
    }

    pub fn parse(
        inputs: impl IntoIterator<Item = InputFormat>,
    ) -> Result<Self, ConfigParsingError> {
        let mut figment = Figment::new();

        for data in inputs {
            figment = match data {
                #[cfg(feature = "config_yaml")]
                InputFormat::Yaml(content) => figment.merge(Yaml::string(&content)),
                #[cfg(feature = "config_json")]
                InputFormat::Json(content) => figment.merge(Json::string(&content)),
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
    Debug,
    Copy,
    Clone,
    Display,
    EnumString,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    Hash,
)]
pub enum FormatType {
    #[serde(rename = "JWT")]
    #[strum(serialize = "JWT")]
    Jwt,
    #[serde(rename = "PHYSICAL_CARD")]
    #[strum(serialize = "PHYSICAL_CARD")]
    PhysicalCard,
    #[serde(rename = "SD_JWT")]
    #[strum(serialize = "SD_JWT")]
    SdJwt,
    #[serde(rename = "SD_JWT_VC")]
    #[strum(serialize = "SD_JWT_VC")]
    SdJwtVc,
    #[serde(rename = "JSON_LD_CLASSIC")]
    #[strum(serialize = "JSON_LD_CLASSIC")]
    JsonLdClassic,
    #[serde(rename = "JSON_LD_BBSPLUS")]
    #[strum(serialize = "JSON_LD_BBSPLUS")]
    JsonLdBbsPlus,
    #[serde(rename = "MDOC")]
    #[strum(serialize = "MDOC")]
    Mdoc,
}

pub type TransportConfig = ConfigBlock<TransportType>;

#[derive(
    Debug,
    Copy,
    Clone,
    Display,
    EnumString,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    AsRefStr,
)]
pub enum TransportType {
    #[serde(rename = "BLE")]
    #[strum(serialize = "BLE")]
    Ble,
    #[serde(rename = "HTTP")]
    #[strum(serialize = "HTTP")]
    Http,
    #[serde(rename = "MQTT")]
    #[strum(serialize = "MQTT")]
    Mqtt,
}

pub type ExchangeConfig = ConfigBlock<ExchangeType>;

#[derive(
    Debug,
    Copy,
    Clone,
    Display,
    EnumString,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    AsRefStr,
)]
pub enum ExchangeType {
    #[serde(rename = "OPENID4VC")]
    #[strum(serialize = "OPENID4VC")]
    OpenId4Vc,
    #[serde(rename = "SCAN_TO_VERIFY")]
    #[strum(serialize = "SCAN_TO_VERIFY")]
    ScanToVerify,
    #[serde(rename = "ISO_MDL")]
    #[strum(serialize = "ISO_MDL")]
    IsoMdl,
}

pub type RevocationConfig = ConfigBlock<RevocationType>;

#[derive(
    Debug, Copy, Clone, Display, EnumString, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
pub enum RevocationType {
    #[serde(rename = "NONE")]
    #[strum(serialize = "NONE")]
    None,
    #[serde(rename = "MDOC_MSO_UPDATE_SUSPENSION")]
    #[strum(serialize = "MDOC_MSO_UPDATE_SUSPENSION")]
    MdocMsoUpdateSuspension,
    #[serde(rename = "LVVC")]
    #[strum(serialize = "LVVC")]
    Lvvc,
    #[serde(rename = "BITSTRINGSTATUSLIST")]
    #[strum(serialize = "BITSTRINGSTATUSLIST")]
    BitstringStatusList,
    #[serde(rename = "TOKENSTATUSLIST")]
    #[strum(serialize = "TOKENSTATUSLIST")]
    TokenStatusList,
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
    Universal,
    #[serde(rename = "MDL")]
    #[strum(serialize = "MDL")]
    MDL,
    #[serde(rename = "SD_JWT_VC_ISSUER_METADATA")]
    #[strum(serialize = "SD_JWT_VC_ISSUER_METADATA")]
    SdJwtVcIssuerMetadata,
    #[serde(rename = "WEBVH")]
    #[strum(serialize = "WEBVH")]
    WebVh,
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
    #[serde(rename = "ARRAY")]
    #[strum(serialize = "ARRAY")]
    Array,
    #[serde(rename = "BOOLEAN")]
    #[strum(serialize = "BOOLEAN")]
    Boolean,
}

pub type KeyAlgorithmConfig = Dict<KeyAlgorithmType, KeyAlgorithmFields>;

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyAlgorithmFields {
    pub display: Value,
    pub order: Option<u64>,
    pub disabled: Option<bool>,
    #[serde(skip_deserializing)]
    pub capabilities: Option<Value>,
}

#[derive(
    Debug,
    Copy,
    Clone,
    Display,
    EnumString,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
)]
pub enum KeyAlgorithmType {
    #[serde(rename = "EDDSA")]
    #[strum(serialize = "EDDSA")]
    Eddsa,
    #[serde(rename = "ES256")]
    #[strum(serialize = "ES256")]
    Es256,
    #[serde(rename = "BBS_PLUS")]
    #[strum(serialize = "BBS_PLUS")]
    BbsPlus,
    #[serde(rename = "DILITHIUM")]
    #[strum(serialize = "DILITHIUM")]
    Dilithium,
}

pub type KeyStorageConfig = ConfigBlock<KeyStorageType>;

#[derive(
    Debug, Copy, Clone, Display, EnumString, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
pub enum KeyStorageType {
    #[serde(rename = "INTERNAL")]
    #[strum(serialize = "INTERNAL")]
    Internal,
    #[serde(rename = "AZURE_VAULT")]
    #[strum(serialize = "AZURE_VAULT")]
    AzureVault,
    #[serde(rename = "PKCS11")]
    #[strum(serialize = "PKCS11")]
    PKCS11,
    #[serde(rename = "SECURE_ELEMENT")]
    #[strum(serialize = "SECURE_ELEMENT")]
    SecureElement,
    #[serde(rename = "REMOTE_SECURE_ELEMENT")]
    #[strum(serialize = "REMOTE_SECURE_ELEMENT")]
    RemoteSecureElement,
}

pub type TaskConfig = ConfigBlock<TaskType>;

#[derive(
    Debug, Copy, Clone, Display, EnumString, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
pub enum TaskType {
    #[serde(rename = "SUSPEND_CHECK")]
    #[strum(serialize = "SUSPEND_CHECK")]
    SuspendCheck,
    #[serde(rename = "RETAIN_PROOF_CHECK")]
    #[strum(serialize = "RETAIN_PROOF_CHECK")]
    RetainProofCheck,
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
            .ok_or_else(|| ConfigValidationError::EntryNotFound(key.to_owned()))?;

        fields
            .deserialize()
            .map_err(|source| ConfigValidationError::FieldsDeserialization {
                key: key.to_owned(),
                source,
            })
    }

    pub fn get_by_type<U>(&self, r#type: T) -> Result<U, ConfigValidationError>
    where
        U: DeserializeOwned,
        T: PartialEq + std::fmt::Display,
    {
        self.iter()
            .find(|(_, v)| v.r#type == r#type)
            .ok_or_else(|| ConfigValidationError::TypeNotFound(r#type.to_string()))?
            .1
            .deserialize()
            .map_err(|source| ConfigValidationError::FieldsDeserialization {
                key: r#type.to_string(),
                source,
            })
    }

    pub fn get_fields(&self, key: &str) -> Result<&Fields<T>, ConfigValidationError> {
        let fields = self
            .0
            .get(key)
            .ok_or(ConfigValidationError::EntryNotFound(key.to_string()))?;

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
            return Err(ConfigValidationError::EntryDisabled(key.to_owned()));
        }

        Ok(fields)
    }

    pub fn get_first_enabled(&self) -> Option<(&str, &Fields<T>)> {
        let mut enabled: Vec<_> = self.iter().filter(|(_, f)| !f.disabled()).collect();
        enabled.sort_by_key(|(_, fields)| fields.order);

        enabled.into_iter().next()
    }

    #[cfg(test)]
    pub fn insert(&mut self, key: String, fields: Fields<T>) {
        self.0.insert(key, fields);
    }
}

impl ConfigBlock<TransportType> {
    pub fn ble_enabled_for(&self, key: &str) -> bool {
        self.transport_enabled_for(key, &TransportType::Ble)
    }

    pub fn mqtt_enabled_for(&self, key: &str) -> bool {
        self.transport_enabled_for(key, &TransportType::Mqtt)
    }

    fn transport_enabled_for(&self, key: &str, transport: &TransportType) -> bool {
        self.get_fields(key)
            .ok()
            .is_some_and(|fields| fields.r#type() == transport && !fields.disabled())
    }

    pub fn get_enabled_transport_type(
        &self,
        r#type: TransportType,
    ) -> Result<&str, ConfigValidationError> {
        Ok(self
            .iter()
            .find(|(_, fields)| fields.r#type == r#type && !fields.disabled())
            .ok_or_else(|| ConfigValidationError::TypeNotFound(r#type.to_string()))?
            .0)
    }
}

impl<T> Default for ConfigBlock<T> {
    fn default() -> Self {
        Self(Dict::default())
    }
}

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Fields<T> {
    pub r#type: T,
    pub display: Value,
    pub order: Option<u64>,
    pub disabled: Option<bool>,
    #[serde(skip_deserializing)]
    pub capabilities: Option<Value>,
    #[serde(default, deserialize_with = "deserialize_params")]
    pub params: Option<Params>,
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
    pub fn deserialize<U: DeserializeOwned>(&self) -> Result<U, serde_json::Error> {
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
            map.remove("params");

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

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    pub public: Option<Value>,
    pub private: Option<Value>,
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
