use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::path::Path;

use figment::Figment;
#[cfg(feature = "config_env")]
use figment::providers::Env;
#[cfg(feature = "config_json")]
use figment::providers::Json;
#[cfg(feature = "config_yaml")]
use figment::providers::Yaml;
use figment::providers::{Data, Format};
use one_dto_mapper::{From, Into};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use serde_with::{DurationSeconds, serde_as, skip_serializing_none};
use shared_types::{CredentialFormat, RevocationMethodId};
use strum::{AsRefStr, Display, EnumString};

use super::{ConfigParsingError, ConfigValidationError};
use crate::model::credential_schema::KeyStorageSecurity;

type Dict<K, V> = BTreeMap<K, V>;

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct NoCustomConfig;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppCustomConfigSerdeDTO<Custom> {
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
    pub format: FormatConfig,
    pub identifier: IdentifierConfig,
    pub issuance_protocol: IssuanceProtocolConfig,
    pub verification_protocol: VerificationProtocolConfig,
    pub transport: TransportConfig,
    pub revocation: RevocationConfig,
    pub did: DidConfig,
    pub datatype: DatatypeConfig,
    pub key_algorithm: KeyAlgorithmConfig,
    pub key_storage: KeyStorageConfig,
    pub key_security_level: KeySecurityLevelConfig,
    pub task: TaskConfig,
    pub trust_management: TrustManagementConfig,
    pub blob_storage: BlobStorageConfig,
    pub cache_entities: CacheEntitiesConfig,
    pub wallet_provider: WalletProviderConfig,
    pub credential_issuer: CredentialIssuerConfig,
    pub verification_engagement: VerificationEngagementConfig,
    pub certificate_validation: CertificateValidationConfig,
    pub signer: SignerConfig,
}

impl CoreConfig {
    pub fn get_datatypes_of_type(&self, datatype: DatatypeType) -> Vec<&str> {
        self.datatype
            .iter()
            .filter_map(|(key, fields)| {
                if fields.r#type == datatype {
                    Some(key.as_str())
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
    pub cache_type: CacheEntityCacheType,

    /// Maximum number of entries the cache can hold (of this `cache_type`)
    ///
    /// When limit reached, the oldest (unused) entries are removed
    pub cache_size: u32,

    /// Duration for soft-refresh
    ///
    /// Duration after which an entry is tried to be refreshed
    /// (if refresh fails, the old cached value is still used)
    #[serde_as(as = "DurationSeconds<i64>")]
    pub refresh_after: time::Duration,

    /// Duration for hard-refresh
    ///
    /// Duration after which an entry is expired and must be refreshed
    /// (if refresh fails, the cached value is ignored and fetching fails)
    #[serde_as(as = "DurationSeconds<i64>")]
    pub cache_refresh_timeout: time::Duration,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialIssuerConfig {
    #[serde(flatten)]
    pub entities: HashMap<String, CredentialIssuerEntry>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialIssuerEntry {
    pub display: ConfigEntryDisplay,
    pub order: Option<u64>,
    pub enabled: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_params")]
    pub params: Option<Params>,
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
    Custom: Serialize + DeserializeOwned,
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

pub type FormatConfig = ConfigBlock<CredentialFormat, FormatType>;

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

pub type TransportConfig = ConfigBlock<String, TransportType>;

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

pub type IssuanceProtocolConfig = ConfigBlock<String, IssuanceProtocolType>;

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
    #[serde(rename = "OPENID4VCI_FINAL1")]
    #[strum(serialize = "OPENID4VCI_FINAL1")]
    OpenId4VciFinal1_0,
}

pub type VerificationProtocolConfig = ConfigBlock<String, VerificationProtocolType>;

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
    #[serde(rename = "OPENID4VP_FINAL1")]
    #[strum(serialize = "OPENID4VP_FINAL1")]
    OpenId4VpFinal1_0,
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

pub type RevocationConfig = ConfigBlock<RevocationMethodId, RevocationType>;

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
    #[serde(rename = "CRL")]
    #[strum(serialize = "CRL")]
    CRL,
}

pub type DidConfig = ConfigBlock<String, DidType>;

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
    #[serde(rename = "PICTURE")]
    #[strum(serialize = "PICTURE")]
    Picture,
    #[serde(rename = "SWIYU_PICTURE")]
    #[strum(serialize = "SWIYU_PICTURE")]
    SwiyuPicture,
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
    pub display: ConfigEntryDisplay,
    pub order: Option<u64>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(skip_deserializing)]
    pub capabilities: Option<Value>,
    #[serde(default)]
    pub holder_priority: u32,
}

impl ConfigFields for KeyAlgorithmFields {
    fn enabled(&self) -> bool {
        self.enabled
    }
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

pub type KeyStorageConfig = ConfigBlock<String, KeyStorageType>;

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

pub type KeySecurityLevelConfig = Dict<KeySecurityLevelType, KeySecurityLevelFields>;

#[derive(
    Debug,
    Copy,
    Clone,
    Display,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    AsRefStr,
    Hash,
    From,
    Into,
)]
#[from(KeyStorageSecurity)]
#[into(KeyStorageSecurity)]
pub enum KeySecurityLevelType {
    #[serde(rename = "BASIC")]
    #[strum(serialize = "BASIC")]
    Basic,
    #[serde(rename = "ENHANCED_BASIC")]
    #[strum(serialize = "ENHANCED_BASIC")]
    EnhancedBasic,
    #[serde(rename = "MODERATE")]
    #[strum(serialize = "MODERATE")]
    Moderate,
    #[serde(rename = "HIGH")]
    #[strum(serialize = "HIGH")]
    High,
}

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeySecurityLevelFields {
    pub display: ConfigEntryDisplay,
    pub order: Option<u64>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(skip_deserializing)]
    pub capabilities: Option<Value>,
    #[serde(default, deserialize_with = "deserialize_params")]
    pub params: Option<Params>,
}

impl ConfigFields for KeySecurityLevelFields {
    fn enabled(&self) -> bool {
        self.enabled
    }
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
    #[serde(rename = "CA")]
    #[strum(serialize = "CA")]
    CertificateAuthority,
}

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentifierFields {
    pub display: ConfigEntryDisplay,
    pub order: Option<u64>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(skip_deserializing)]
    pub capabilities: Option<Value>,
}

impl ConfigFields for IdentifierFields {
    fn enabled(&self) -> bool {
        self.enabled
    }
}

pub type TaskConfig = ConfigBlock<String, TaskType>;

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
    #[serde(rename = "INTERACTION_EXPIRATION_CHECK")]
    #[strum(serialize = "INTERACTION_EXPIRATION_CHECK")]
    InteractionExpirationCheck,
}

pub type TrustManagementConfig = ConfigBlock<String, TrustManagementType>;

#[derive(
    Debug, Copy, Clone, Display, EnumString, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
pub enum TrustManagementType {
    #[serde(rename = "SIMPLE_TRUST_LIST")]
    #[strum(serialize = "SIMPLE_TRUST_LIST")]
    SimpleTrustList,
}

pub type BlobStorageConfig = Dict<BlobStorageType, BlobStorageFields>;

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
pub enum BlobStorageType {
    #[serde(rename = "DB")]
    #[strum(serialize = "DB")]
    Db,
}

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlobStorageFields {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default, deserialize_with = "deserialize_params")]
    pub params: Option<Params>,
}

impl ConfigFields for BlobStorageFields {
    fn enabled(&self) -> bool {
        self.enabled
    }
}

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
pub enum WalletProviderType {
    #[serde(rename = "PROCIVIS_ONE")]
    #[strum(serialize = "PROCIVIS_ONE")]
    ProcivisOne,
}

pub type WalletProviderConfig = ConfigBlock<String, WalletProviderType>;

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
    Hash,
)]
pub enum VerificationEngagement {
    #[serde(rename = "QR_CODE")]
    #[strum(serialize = "QR_CODE")]
    QrCode,
    #[serde(rename = "NFC")]
    #[strum(serialize = "NFC")]
    NFC,
}

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationEngagementFields {
    pub display: ConfigEntryDisplay,
    pub order: Option<u64>,
    pub enabled: Option<bool>,
}

impl VerificationEngagementFields {
    pub fn enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }
}

pub type VerificationEngagementConfig = Dict<VerificationEngagement, VerificationEngagementFields>;

#[serde_as]
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateValidationConfig {
    #[serde(default)]
    #[serde_as(as = "DurationSeconds<i64>")]
    pub leeway: time::Duration,
}

pub type SignerConfig = ConfigBlock<String, SignerType>;

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
    Hash,
)]
pub enum SignerType {
    #[serde(rename = "REGISTRATION_CERTIFICATE")]
    #[strum(serialize = "REGISTRATION_CERTIFICATE")]
    RegistrationCertificate,
}

// Alias for the collection of traits we want config keys to implement.
pub trait ConfigKey: Debug + Display + Clone + Ord {}
// Blanket impl
impl<T: Debug + Display + Clone + Ord> ConfigKey for T {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ConfigBlock<K: ConfigKey, T>(Dict<K, Fields<T>>);

impl<K, T> ConfigBlock<K, T>
where
    K: ConfigKey,
    T: Serialize + Clone,
{
    // Deserialize current fields for a given key into a type.
    // Private and public fields will be merged.
    pub fn get<U, Q: ?Sized + Display + Ord>(&self, key: &Q) -> Result<U, ConfigValidationError>
    where
        K: Borrow<Q>,
        U: DeserializeOwned,
    {
        let fields = self
            .0
            .get(key)
            .ok_or_else(|| ConfigValidationError::EntryNotFound(key.to_string()))?;

        fields
            .deserialize()
            .map_err(|source| ConfigValidationError::FieldsDeserialization {
                key: key.to_string(),
                source,
            })
    }

    pub fn get_type<Q: ?Sized + Display + Ord>(&self, key: &Q) -> Result<T, ConfigValidationError>
    where
        K: Borrow<Q>,
    {
        self.get_fields(key).map(|fields| fields.r#type.clone())
    }

    pub fn get_by_type<U>(&self, r#type: T) -> Result<U, ConfigValidationError>
    where
        U: DeserializeOwned,
        T: PartialEq + Display,
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

    pub fn get_key_by_type(&self, r#type: T) -> Result<K, ConfigValidationError>
    where
        T: PartialEq + Display,
    {
        Ok(self
            .iter()
            .find(|(_, v)| v.r#type == r#type)
            .ok_or_else(|| ConfigValidationError::TypeNotFound(r#type.to_string()))?
            .0
            .clone())
    }

    pub fn get_fields<Q: ?Sized + Display + Ord>(
        &self,
        key: &Q,
    ) -> Result<&Fields<T>, ConfigValidationError>
    where
        K: Borrow<Q>,
    {
        let fields = self
            .0
            .get(key)
            .ok_or(ConfigValidationError::EntryNotFound(key.to_string()))?;

        Ok(fields)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&K, &Fields<T>)> {
        self.0.iter().map(|(k, v)| (k as _, v))
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&K, &mut Fields<T>)> {
        self.0.iter_mut().map(|(k, v)| (k as _, v))
    }

    #[cfg(test)]
    pub fn insert(&mut self, key: K, fields: Fields<T>) {
        self.0.insert(key, fields);
    }
}

impl ConfigBlock<String, TransportType> {
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

trait ConfigFields {
    fn enabled(&self) -> bool;
}

pub trait ConfigExt<K, T> {
    fn iter_enabled<'a>(&'a self) -> impl Iterator<Item = (&'a K, &'a T)>
    where
        K: 'a,
        T: 'a;

    fn get_if_enabled<Q>(&self, key: &Q) -> Result<&T, ConfigValidationError>
    where
        K: Borrow<Q> + Ord,
        Q: ?Sized + Ord + Display;
}

impl<K, T> ConfigExt<K, T> for Dict<K, T>
where
    K: Ord,
    T: ConfigFields,
{
    fn iter_enabled<'a>(&'a self) -> impl Iterator<Item = (&'a K, &'a T)>
    where
        K: 'a,
        T: 'a,
    {
        self.iter().filter(|(_, value)| value.enabled())
    }

    fn get_if_enabled<Q>(&self, key: &Q) -> Result<&T, ConfigValidationError>
    where
        K: Borrow<Q> + Ord,
        Q: ?Sized + Ord + Display,
    {
        let fields = self
            .get(key)
            .ok_or(ConfigValidationError::EntryNotFound(key.to_string()))?;
        if !fields.enabled() {
            return Err(ConfigValidationError::EntryDisabled(key.to_string()));
        }
        Ok(fields)
    }
}

impl<K: ConfigKey, T> ConfigExt<K, Fields<T>> for ConfigBlock<K, T> {
    fn iter_enabled<'a>(&'a self) -> impl Iterator<Item = (&'a K, &'a Fields<T>)>
    where
        T: 'a,
    {
        self.0.iter_enabled()
    }

    fn get_if_enabled<Q>(&self, key: &Q) -> Result<&Fields<T>, ConfigValidationError>
    where
        K: Borrow<Q> + Ord,
        Q: ?Sized + Ord + Display,
    {
        self.0.get_if_enabled(key)
    }
}
impl<K: ConfigKey, T> Default for ConfigBlock<K, T> {
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

impl<T: Display> From<T> for ConfigEntryDisplay {
    fn from(value: T) -> Self {
        Self::TranslationId(value.to_string())
    }
}

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Fields<T> {
    pub r#type: T,
    pub display: ConfigEntryDisplay,
    pub order: Option<u64>,
    /// Selection priority of the given provider (used to disambiguate between multiple providers of
    /// the same type). Higher priority providers will be preferred over lower priority ones.
    pub priority: Option<u64>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(skip_deserializing)]
    pub capabilities: Option<Value>,
    #[serde(default, deserialize_with = "deserialize_params")]
    pub params: Option<Params>,
}

fn default_true() -> bool {
    true
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

impl<T> ConfigFields for Fields<T> {
    fn enabled(&self) -> bool {
        self.enabled
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
    use similar_asserts::assert_eq;

    use super::*;

    #[test]
    fn test_merge_fields_with_public_and_private_params() {
        let fields = Fields {
            r#type: "JWT".to_string(),
            display: "jwt".into(),
            order: Some(0),
            priority: None,
            enabled: true,
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
                "enabled": true,
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
