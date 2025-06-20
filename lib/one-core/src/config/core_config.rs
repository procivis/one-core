use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Debug;
use std::path::Path;

use figment::Figment;
#[cfg(feature = "config_env")]
use figment::providers::Env;
#[cfg(feature = "config_json")]
use figment::providers::Json;
#[cfg(feature = "config_yaml")]
use figment::providers::Yaml;
use figment::providers::{Data, Format};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use serde_with::{DurationSeconds, serde_as, skip_serializing_none};
use strum::{AsRefStr, Display, EnumString};

use super::{ConfigParsingError, ConfigValidationError};
use crate::model::credential_schema::WalletStorageTypeEnum;

type Dict<K, V> = BTreeMap<K, V>;

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct NoCustomConfig;

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppCustomConfigSerdeDTO<Custom> {
    #[serde(default)]
    pub(super) app: Custom,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppConfig<Custom> {
    pub core: CoreConfig,
    #[serde(default)]
    pub app: Custom,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoreConfig {
    pub(crate) format: FormatConfig,
    pub(crate) identifier: IdentifierConfig,
    pub(crate) issuance_protocol: IssuanceProtocolConfig,
    pub(crate) verification_protocol: VerificationProtocolConfig,
    pub(crate) transport: TransportConfig,
    pub(crate) revocation: RevocationConfig,
    pub(crate) did: DidConfig,
    pub(crate) datatype: DatatypeConfig,
    pub(crate) key_algorithm: KeyAlgorithmConfig,
    pub(crate) holder_key_storage: HolderKeyStorageConfig,
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

pub enum InputFormat {
    #[cfg(feature = "config_yaml")]
    Yaml(Data<Yaml>),
    #[cfg(feature = "config_json")]
    Json(Data<Json>),
}

impl InputFormat {
    #[cfg(feature = "config_yaml")]
    pub fn yaml_file(p: impl AsRef<Path>) -> InputFormat {
        InputFormat::Yaml(Yaml::file(p))
    }

    #[cfg(feature = "config_yaml")]
    pub fn yaml_str(s: impl AsRef<str>) -> InputFormat {
        InputFormat::Yaml(Yaml::string(s.as_ref()))
    }

    #[cfg(feature = "config_json")]
    pub fn json_file(p: impl AsRef<Path>) -> InputFormat {
        InputFormat::Json(Json::file(p))
    }

    #[cfg(feature = "config_json")]
    pub fn json_str(s: impl AsRef<str>) -> InputFormat {
        InputFormat::Json(Json::string(s.as_ref()))
    }
}

impl<Custom> AppConfig<Custom>
where
    Custom: Serialize + DeserializeOwned + Default,
{
    pub fn from_files(files: &[impl AsRef<std::path::Path>]) -> Result<Self, ConfigParsingError> {
        let mut inputs: Vec<InputFormat> = Vec::with_capacity(files.len());

        for path in files {
            #[cfg(feature = "config_yaml")]
            if path
                .as_ref()
                .extension()
                .is_some_and(|ext| ext == "yml" || ext == "yaml")
            {
                inputs.push(InputFormat::Yaml(Yaml::file(path)));
                continue;
            }

            #[cfg(feature = "config_json")]
            if path.as_ref().extension() == Some("json".as_ref()) {
                inputs.push(InputFormat::Json(Json::file(path)));
                continue;
            }

            return Err(ConfigParsingError::GeneralParsingError(format!(
                "Unsupported file or missing file extension: {:?}",
                path.as_ref().to_str()
            )));
        }

        AppConfig::parse(inputs)
    }

    #[cfg(feature = "config_yaml")]
    pub fn from_yaml(
        configs: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<Self, ConfigParsingError> {
        let inputs = configs
            .into_iter()
            .map(|s| Yaml::string(s.as_ref()))
            .map(InputFormat::Yaml);

        AppConfig::parse(inputs)
    }

    pub fn parse(
        inputs: impl IntoIterator<Item = InputFormat>,
    ) -> Result<Self, ConfigParsingError> {
        let mut figment = Figment::new();

        for data in inputs {
            figment = match data {
                #[cfg(feature = "config_yaml")]
                InputFormat::Yaml(content) => figment.merge(content),
                #[cfg(feature = "config_json")]
                InputFormat::Json(content) => figment.merge(content),
            };
        }

        #[cfg(feature = "config_env")]
        {
            figment = figment.merge(Env::prefixed("ONE_").split("__").lowercase(false));
        }

        let core = figment
            .extract::<CoreConfig>()
            .map_err(|e| ConfigParsingError::GeneralParsingError(e.to_string()))?;
        let custom = figment
            .extract::<AppCustomConfigSerdeDTO<Custom>>()
            .map_err(|e| ConfigParsingError::GeneralParsingError(e.to_string()))?;
        Ok(Self {
            core,
            app: custom.app,
        })
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

pub type IssuanceProtocolConfig = ConfigBlock<IssuanceProtocolType>;

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
pub enum IssuanceProtocolType {
    #[serde(rename = "OPENID4VCI_DRAFT13")]
    #[strum(serialize = "OPENID4VCI_DRAFT13")]
    OpenId4VciDraft13,
    #[serde(rename = "OPENID4VCI_DRAFT13_SWIYU")]
    #[strum(serialize = "OPENID4VCI_DRAFT13_SWIYU")]
    OpenId4VciDraft13Swiyu,
}

pub type VerificationProtocolConfig = ConfigBlock<VerificationProtocolType>;

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
pub enum VerificationProtocolType {
    #[serde(rename = "OPENID4VP_DRAFT20")]
    #[strum(serialize = "OPENID4VP_DRAFT20")]
    OpenId4VpDraft20,
    #[serde(rename = "OPENID4VP_DRAFT20_SWIYU")]
    #[strum(serialize = "OPENID4VP_DRAFT20_SWIYU")]
    OpenId4VpDraft20Swiyu,
    #[serde(rename = "OPENID4VP_DRAFT25")]
    #[strum(serialize = "OPENID4VP_DRAFT25")]
    OpenId4VpDraft25,
    #[serde(rename = "SCAN_TO_VERIFY")]
    #[strum(serialize = "SCAN_TO_VERIFY")]
    ScanToVerify,
    #[serde(rename = "ISO_MDL")]
    #[strum(serialize = "ISO_MDL")]
    IsoMdl,
    #[serde(rename = "OPENID4VP_PROXIMITY_DRAFT00")]
    #[strum(serialize = "OPENID4VP_PROXIMITY_DRAFT00")]
    OpenId4VpProximityDraft00,
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
    #[serde(rename = "UNIVERSAL_RESOLVER")]
    #[strum(serialize = "UNIVERSAL_RESOLVER")]
    Universal,
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

pub type HolderKeyStorageConfig = Dict<WalletStorageTypeEnum, HolderKeyStorageFields>;

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HolderKeyStorageFields {
    pub display: ConfigEntryDisplay,
    pub order: Option<u64>,
    pub enabled: Option<bool>,
}

pub type KeyAlgorithmConfig = Dict<KeyAlgorithmType, KeyAlgorithmFields>;

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyAlgorithmFields {
    pub display: ConfigEntryDisplay,
    pub order: Option<u64>,
    pub enabled: Option<bool>,
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
    AsRefStr,
)]
pub enum KeyAlgorithmType {
    #[serde(rename = "EDDSA")]
    #[strum(serialize = "EDDSA")]
    Eddsa,
    #[serde(rename = "ECDSA")]
    #[strum(serialize = "ECDSA")]
    Ecdsa,
    #[serde(rename = "BBS_PLUS")]
    #[strum(serialize = "BBS_PLUS")]
    BbsPlus,
    #[serde(rename = "DILITHIUM")]
    #[strum(serialize = "DILITHIUM")]
    Dilithium,
}

pub type KeyStorageConfig = ConfigBlock<KeyStorageType>;

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

pub type IdentifierConfig = Dict<IdentifierType, IdentifierFields>;

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
    AsRefStr,
)]
pub enum IdentifierType {
    #[serde(rename = "DID")]
    #[strum(serialize = "DID")]
    Did,
    #[serde(rename = "CERTIFICATE")]
    #[strum(serialize = "CERTIFICATE")]
    Certificate,
    #[serde(rename = "KEY")]
    #[strum(serialize = "KEY")]
    Key,
}

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentifierFields {
    pub display: ConfigEntryDisplay,
    pub order: Option<u64>,
    pub enabled: Option<bool>,
    #[serde(skip_deserializing)]
    pub capabilities: Option<Value>,
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
    #[serde(rename = "CERTIFICATE_CHECK")]
    #[strum(serialize = "CERTIFICATE_CHECK")]
    CertificateCheck,
    #[serde(rename = "HOLDER_CHECK_CREDENTIAL_STATUS")]
    #[strum(serialize = "HOLDER_CHECK_CREDENTIAL_STATUS")]
    HolderCheckCredentialStatus,
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

        if !fields.enabled() {
            return Err(ConfigValidationError::EntryDisabled(key.to_owned()));
        }

        Ok(fields)
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
            .is_some_and(|fields| fields.r#type() == transport && fields.enabled())
    }

    pub fn get_enabled_transport_type(
        &self,
        r#type: TransportType,
    ) -> Result<&str, ConfigValidationError> {
        Ok(self
            .iter()
            .find(|(_, fields)| fields.r#type == r#type && fields.enabled())
            .ok_or_else(|| ConfigValidationError::TypeNotFound(r#type.to_string()))?
            .0)
    }
}

impl<T> Default for ConfigBlock<T> {
    fn default() -> Self {
        Self(Dict::default())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ConfigEntryDisplay {
    TranslationId(String),
    Translated(HashMap<String, String>),
}

impl<T: Into<String>> From<T> for ConfigEntryDisplay {
    fn from(value: T) -> Self {
        Self::TranslationId(value.into())
    }
}

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Fields<T> {
    pub r#type: T,
    pub display: ConfigEntryDisplay,
    pub order: Option<u64>,
    pub enabled: Option<bool>,
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

    pub fn enabled(&self) -> bool {
        self.enabled != Some(false)
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
    pub(crate) fn merge(&self) -> Option<Value> {
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
            display: "jwt".into(),
            order: Some(0),
            enabled: None,
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
