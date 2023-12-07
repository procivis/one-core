use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    io::Cursor,
    str::FromStr,
};

use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};
use strum_macros::{Display, EnumString};

use super::{ConfigParsingError, ConfigValidationError};

type Dict<K, V> = BTreeMap<K, V>;

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
}

impl CoreConfig {
    pub fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self, ConfigParsingError> {
        let file = std::fs::File::open(&path)?;

        let config = match path.as_ref().extension() {
            Some(v) if v == "json" => serde_json::from_reader(file)?,
            _ => serde_yaml::from_reader(file)?,
        };

        Ok(config)
    }

    pub fn from_yaml_str(config: impl AsRef<str>) -> Result<Self, ConfigParsingError> {
        Ok(serde_yaml::from_reader(Cursor::new(config.as_ref()))?)
    }
}

pub type FormatConfig = ConfigBlock<FormatType, String>;

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
    #[serde(rename = "JSON_LD")]
    #[strum(serialize = "JSON_LD")]
    JsonLd,
    #[serde(rename = "MDOC")]
    #[strum(serialize = "MDOC")]
    Mdoc,
}

pub type ExchangeConfig = ConfigBlock<ExchangeType, String>;

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

pub type TransportConfig = ConfigBlock<TransportType, String>;

#[derive(
    Debug, Copy, Clone, Display, EnumString, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
pub enum TransportType {
    #[serde(rename = "HTTP")]
    Http,
}

pub type RevocationConfig = ConfigBlock<RevocationType, String>;

#[derive(
    Debug, Copy, Clone, Display, EnumString, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
pub enum RevocationType {
    #[serde(rename = "NONE")]
    #[strum(serialize = "NONE")]
    None,
    #[serde(rename = "STATUSLIST2021")]
    #[strum(serialize = "STATUSLIST2021")]
    StatusList2021,
    #[serde(rename = "LVVC")]
    #[strum(serialize = "LVVC")]
    Lvvc,
}

pub type DidConfig = ConfigBlock<DidType, String>;

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
}

pub type DatatypeConfig = ConfigBlock<String, DatatypeType>;

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
}

pub type KeyAlgorithmConfig = ConfigBlock<KeyAlgorithmType, String>;

#[derive(
    Debug, Copy, Clone, Display, EnumString, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
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
    #[serde(rename = "ES256")]
    #[strum(serialize = "ES256")]
    Es256,
}

pub type KeyStorageConfig = ConfigBlock<KeyStorageType, String>;

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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ConfigBlock<K: Ord, V>(Dict<K, Fields<V>>);

impl<K, T> ConfigBlock<K, T>
where
    K: Ord,
    T: Serialize + DeserializeOwned + Clone,
{
    // Deserialize current fields for a given key into a type.
    // Private and public fields will be merged.
    // Note: We use the `impl ToString` bound for the key since `strum::EnumString` derives it
    pub fn get<U>(&self, key: impl ToString) -> Result<U, ConfigValidationError>
    where
        U: DeserializeOwned,
        K: FromStr,
    {
        let key = key.to_string();
        let parsed_key =
            K::from_str(&key).map_err(|_| ConfigValidationError::InvalidKey(key.to_string()))?;

        match self.0.get(&parsed_key) {
            None => Err(ConfigValidationError::KeyNotFound(key)),
            Some(fields) => fields
                .deserialize()
                .map_err(|source| ConfigValidationError::FieldsDeserialization { key, source }),
        }
    }

    pub fn get_fields(&self, key: &str) -> Result<&Fields<T>, ConfigValidationError>
    where
        K: FromStr,
    {
        let parsed_key =
            K::from_str(key).map_err(|_| ConfigValidationError::InvalidKey(key.to_string()))?;

        self.0
            .get(&parsed_key)
            .ok_or(ConfigValidationError::KeyNotFound(key.to_string()))
    }

    pub fn as_inner(&self) -> &Dict<K, Fields<T>> {
        &self.0
    }

    #[cfg(test)]
    pub fn insert(&mut self, key: K, fields: Fields<T>) {
        self.0.insert(key, fields);
    }
}

impl<K: Ord, T> Default for ConfigBlock<K, T> {
    fn default() -> Self {
        Self(Dict::default())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Fields<T> {
    pub(crate) r#type: T,
    pub(crate) display: String,
    pub(crate) order: Option<u64>,
    pub(crate) disabled: Option<bool>,
    #[serde(deserialize_with = "deserialize_params")]
    pub(crate) params: Option<Params>,
}

impl<T> Fields<T>
where
    T: Serialize + Clone,
{
    pub fn r#type(&self) -> &T {
        &self.r#type
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
    use super::*;

    #[test]
    fn test_parses_current_configuration() {
        CoreConfig::from_file("../../config.yml").unwrap();
    }

    #[test]
    fn test_merge_fields_with_public_and_private_params() {
        let fields = Fields {
            r#type: "JWT".to_string(),
            display: "jwt".to_string(),
            order: Some(0),
            disabled: None,
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
