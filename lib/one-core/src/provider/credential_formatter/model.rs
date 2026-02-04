//! Methods for signing and verifying credentials, as well as `struct`s and `enum`s.

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};

use async_trait::async_trait;
use indexmap::IndexMap;
use one_crypto::SignerError;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::skip_serializing_none;
use shared_types::DidValue;
use standardized_types::jwk::PublicJwk;
use strum::{Display, IntoStaticStr};
use time::OffsetDateTime;
use url::Url;

use super::error::FormatterError;
use super::vcdm::VcdmCredential;
use crate::config::core_config::{
    DidType, IdentifierType, IssuanceProtocolType, KeyAlgorithmType, KeyStorageType,
    RevocationType, VerificationProtocolType,
};
use crate::model::certificate::Certificate;
use crate::model::credential_schema::{LayoutProperties, LayoutType};
use crate::model::identifier::Identifier;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;

pub type AuthenticationFn = Box<dyn SignatureProvider>;
pub type VerificationFn = Box<dyn TokenVerifier>;

pub enum PublicKeySource<'a> {
    Did {
        did: Cow<'a, DidValue>,
        key_id: Option<&'a str>,
    },
    X5c {
        x5c: &'a [String],
    },
    Jwk {
        jwk: Cow<'a, PublicJwk>,
    },
}

impl<'a> From<&'a PublicJwk> for PublicKeySource<'a> {
    fn from(value: &'a PublicJwk) -> Self {
        Self::Jwk {
            jwk: Cow::Borrowed(value),
        }
    }
}

/// Method for verifying credential.
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub trait TokenVerifier: Send + Sync {
    async fn verify<'a>(
        &self,
        public_key_source: PublicKeySource<'a>,
        algorithm: KeyAlgorithmType,
        token: &'a [u8],
        signature: &'a [u8],
    ) -> Result<(), SignerError>;

    fn key_algorithm_provider(&self) -> &dyn KeyAlgorithmProvider;
}

/// Method for signing credential with private key without exposing it.
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub trait SignatureProvider: Send + Sync {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError>;
    fn get_key_id(&self) -> Option<String>;
    fn get_key_algorithm(&self) -> Result<KeyAlgorithmType, String>;
    fn jose_alg(&self) -> Option<String>;
    fn get_public_key(&self) -> Vec<u8>;
}

pub trait SettableClaims {
    fn set_claims(&mut self, claims: CredentialClaim) -> Result<(), FormatterError>;
}

#[skip_serializing_none]
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CertificateDetails {
    pub chain: String,
    pub fingerprint: String,
    pub expiry: OffsetDateTime,
    pub subject_common_name: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum IdentifierDetails {
    Did(DidValue),
    Certificate(CertificateDetails),
    Key(PublicJwk),
}

impl IdentifierDetails {
    #[allow(dead_code)]
    pub(crate) fn did_value(&self) -> Option<&DidValue> {
        match &self {
            IdentifierDetails::Did(did_value) => Some(did_value),
            _ => None,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn certificate_details(&self) -> Option<&CertificateDetails> {
        match &self {
            IdentifierDetails::Certificate(certificate) => Some(certificate),
            _ => None,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn public_key_jwk(&self) -> Option<&PublicJwk> {
        match &self {
            IdentifierDetails::Key(key) => Some(key),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DetailCredential {
    pub id: Option<String>,
    pub issuance_date: Option<OffsetDateTime>,
    pub valid_from: Option<OffsetDateTime>,
    pub valid_until: Option<OffsetDateTime>,
    pub update_at: Option<OffsetDateTime>,
    pub invalid_before: Option<OffsetDateTime>,
    pub issuer: IdentifierDetails,
    pub subject: Option<IdentifierDetails>,
    pub claims: CredentialSubject,
    pub status: Vec<CredentialStatus>,
    pub credential_schema: Option<CredentialSchema>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CredentialClaim {
    pub selectively_disclosable: bool,
    pub metadata: bool,
    pub value: CredentialClaimValue,
}

impl CredentialClaim {
    /// Recursively sets the metadata flag.
    pub(crate) fn set_metadata(&mut self, metadata: bool) {
        self.metadata = metadata;
        self.value.set_metadata(metadata);
    }
}

impl Serialize for CredentialClaim {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_json::Value::from(self.clone()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CredentialClaim {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        CredentialClaim::try_from(serde_json::Value::deserialize(deserializer)?)
            .map_err(Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum CredentialClaimValue {
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<CredentialClaim>),
    Object(HashMap<String, CredentialClaim>),
}

impl CredentialClaimValue {
    /// Recursively sets the metadata flag.
    pub(crate) fn set_metadata(&mut self, metadata: bool) {
        match self {
            CredentialClaimValue::Bool(_)
            | CredentialClaimValue::Number(_)
            | CredentialClaimValue::String(_) => {
                // nothing to do
            }
            CredentialClaimValue::Array(arr) => {
                arr.iter_mut().for_each(|elem| elem.set_metadata(metadata))
            }
            CredentialClaimValue::Object(obj) => {
                obj.iter_mut().for_each(|(_, v)| v.set_metadata(metadata))
            }
        }
    }
}

impl Serialize for CredentialClaimValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_json::Value::from(self.clone()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CredentialClaimValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        CredentialClaimValue::try_from(serde_json::Value::deserialize(deserializer)?)
            .map_err(Error::custom)
    }
}

#[derive(Debug, Clone)]
pub struct CredentialSubject {
    // relevant only for VCDM
    pub id: Option<Url>,
    pub claims: HashMap<String, CredentialClaim>,
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchema {
    pub id: String,
    pub r#type: String,
    pub metadata: Option<CredentialSchemaMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchemaMetadata {
    pub layout_properties: LayoutProperties,
    pub layout_type: LayoutType,
}

impl CredentialSchema {
    pub fn new(id: String, r#type: String, metadata: Option<CredentialSchemaMetadata>) -> Self {
        Self {
            id,
            r#type,
            metadata,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PublishedClaim {
    pub key: String,
    pub value: PublishedClaimValue,
    pub datatype: Option<String>,
    pub array_item: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub enum PublishedClaimValue {
    Bool(bool),
    Float(f64),
    Integer(i64),
    String(String),
}

impl TryFrom<PublishedClaimValue> for serde_json::Value {
    type Error = FormatterError;

    fn try_from(value: PublishedClaimValue) -> Result<Self, Self::Error> {
        Ok(match value {
            PublishedClaimValue::Bool(value) => serde_json::Value::Bool(value),
            PublishedClaimValue::Float(value) => serde_json::Value::Number(
                serde_json::Number::from_f64(value).ok_or(FormatterError::FloatValueIsNaN)?,
            ),
            PublishedClaimValue::Integer(value) => {
                serde_json::Value::Number(serde_json::Number::from(value))
            }
            PublishedClaimValue::String(value) => serde_json::Value::String(value),
        })
    }
}

impl Display for PublishedClaimValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bool(value) => write!(f, "{value}"),
            Self::Float(value) => write!(f, "{value}"),
            Self::Integer(value) => write!(f, "{value}"),
            Self::String(value) => write!(f, "{value}"),
        }
    }
}

impl From<&str> for PublishedClaimValue {
    fn from(value: &str) -> Self {
        PublishedClaimValue::String(value.to_string())
    }
}

impl PartialEq<str> for PublishedClaimValue {
    fn eq(&self, other: &str) -> bool {
        if let PublishedClaimValue::String(value) = self {
            value == other
        } else {
            false
        }
    }
}

#[derive(Debug)]
pub struct CredentialData {
    pub vcdm: VcdmCredential,
    pub claims: Vec<PublishedClaim>,
    pub holder_identifier: Option<Identifier>,
    pub holder_key_id: Option<String>,
    pub issuer_certificate: Option<Certificate>,
}

#[derive(Debug)]
pub struct CredentialSchemaData {
    pub id: Option<String>,
    pub r#type: Option<String>,
    pub context: Option<String>,
    pub name: String,
    pub metadata: Option<CredentialSchemaMetadata>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialStatus {
    pub id: Option<Url>,
    pub r#type: String,
    pub status_purpose: Option<String>,
    #[serde(flatten)]
    pub additional_fields: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Default, Clone)]
pub struct HolderBindingCtx {
    pub nonce: String,
    pub audience: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialPresentation {
    pub token: String,
    pub disclosed_keys: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VCCredentialClaimSchemaResponse {
    pub key: String,
    pub id: String,
    pub datatype: String,
    pub required: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VCCredentialSchemaResponse {
    pub name: String,
    pub id: String,
    pub claims: Vec<VCCredentialClaimSchemaResponse>,
}

#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FormatterCapabilities {
    pub features: Vec<Features>,
    pub selective_disclosure: Vec<SelectiveDisclosure>,
    pub issuance_did_methods: Vec<DidType>,
    pub issuance_exchange_protocols: Vec<IssuanceProtocolType>,
    pub proof_exchange_protocols: Vec<VerificationProtocolType>,
    pub revocation_methods: Vec<RevocationType>,
    pub signing_key_algorithms: Vec<KeyAlgorithmType>,
    pub verification_key_algorithms: Vec<KeyAlgorithmType>,
    pub verification_key_storages: Vec<KeyStorageType>,
    pub datatypes: Vec<String>,
    pub allowed_schema_ids: Vec<String>,
    pub forbidden_claim_names: Vec<String>,
    pub issuance_identifier_types: Vec<IdentifierType>,
    pub verification_identifier_types: Vec<IdentifierType>,
    pub holder_identifier_types: Vec<IdentifierType>,
    pub holder_key_algorithms: Vec<KeyAlgorithmType>,
    pub holder_did_methods: Vec<DidType>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Features {
    SelectiveDisclosure,
    SupportsCredentialDesign,
    RequiresSchemaId,
    RequiresSchemaIdForExternal,
    RequiresPresentationEncryption,
    SupportsCombinedPresentation,
    SupportsTxCode,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SelectiveDisclosure {
    AnyLevel,
    SecondLevel,
}

#[derive(Debug, Serialize, Deserialize, Display, IntoStaticStr)]
pub enum Context {
    #[serde(rename = "https://www.w3.org/2018/credentials/v1")]
    #[strum(to_string = "https://www.w3.org/2018/credentials/v1")]
    CredentialsV1,

    #[serde(rename = "https://www.w3.org/ns/credentials/v2")]
    #[strum(to_string = "https://www.w3.org/ns/credentials/v2")]
    CredentialsV2,

    #[serde(rename = "https://w3c.github.io/vc-bitstring-status-list/contexts/v1.jsonld")]
    #[strum(to_string = "https://w3c.github.io/vc-bitstring-status-list/contexts/v1.jsonld")]
    BitstringStatusList,

    #[serde(rename = "https://w3id.org/security/data-integrity/v2")]
    #[strum(to_string = "https://w3id.org/security/data-integrity/v2")]
    DataIntegrityV2,
}

impl Context {
    pub fn to_url(&self) -> Url {
        #[allow(clippy::expect_used)]
        Url::parse(self.into()).expect("Context is always a URL")
    }
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum Issuer {
    Url(Url),
    Object {
        id: Url,
        #[serde(default)]
        name: Option<Name>,
        #[serde(flatten)]
        rest: Option<IndexMap<String, serde_json::Value>>,
    },
}

impl Issuer {
    pub fn to_did_value(&self) -> Result<DidValue, FormatterError> {
        match self {
            Self::Object { id, .. } => Ok(id.to_string().parse().map_err(|_| {
                FormatterError::Failed("Parsing did from object failed".to_string())
            })?),
            Self::Url(url) => Ok(url
                .as_str()
                .parse()
                .map_err(|_| FormatterError::Failed("Parsing did from url failed".to_string()))?),
        }
    }

    pub fn as_url(&self) -> &Url {
        match self {
            Issuer::Url(url) => url,
            Issuer::Object { id, .. } => id,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum Name {
    Languages(Vec<LanguageValue>),
    Language(LanguageValue),
    String(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum Description {
    Languages(Vec<LanguageValue>),
    Language(LanguageValue),
    String(String),
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct LanguageValue {
    #[serde(rename = "@value")]
    value: String,
    #[serde(default, rename = "@language")]
    language: Option<String>,
    #[serde(default, rename = "@direction")]
    direction: Option<String>,
}
