//! Methods for signing and verifying credentials, as well as `struct`s and `enum`s.

use std::borrow::Cow;
use std::collections::HashMap;

use async_trait::async_trait;
use indexmap::IndexMap;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::skip_serializing_none;
use shared_types::{DidValue, SerializedCredential};
use standardized_types::jwk::PublicJwk;
use strum::{Display, IntoStaticStr};
use time::OffsetDateTime;
use url::Url;

use super::error::FormatterError;
use super::mdoc_formatter::MdocCredential;
use super::sdjwtvc_formatter::model::SdJwtVcCredential;
use super::vcdm::VcdmCredential;
use crate::config::core_config::{
    DidType, IdentifierType, IssuanceProtocolType, KeyAlgorithmType, KeyStorageType,
    RevocationType, VerificationProtocolType,
};
use crate::error::ContextWithErrorCode;
use crate::model::certificate::Certificate;
use crate::model::identifier::Identifier;
use crate::proto::jwt::TokenError;
use crate::provider::did_method::error::DidMethodError;
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;

pub type AuthenticationFn = Box<dyn SignatureProvider>;
pub type VerificationFn = Box<dyn TokenVerifier>;

#[derive(Clone, Debug, PartialEq)]
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
    ) -> Result<(), TokenError>;

    fn key_algorithm_provider(&self) -> &dyn KeyAlgorithmProvider;
}

/// Method for signing credential with private key without exposing it.
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub trait SignatureProvider: Send + Sync {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyAlgorithmError>;
    fn get_key_id(&self) -> Option<String>;
    fn get_key_algorithm(&self) -> Result<KeyAlgorithmType, KeyAlgorithmError>;
    fn jose_alg(&self) -> Result<String, KeyAlgorithmError>;
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
    #[serde(default)]
    pub x5_references: X5References,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct X5References {
    pub x5c: bool,
    pub x5u: bool,
    pub x5t_s256: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum IdentifierDetails {
    Did(DidValue),
    Certificate(CertificateDetails),
    Key(PublicJwk),
}

impl IdentifierDetails {
    pub(crate) fn identifier_type(&self) -> IdentifierType {
        match &self {
            IdentifierDetails::Key(_) => IdentifierType::Key,
            IdentifierDetails::Certificate(_) => IdentifierType::Certificate,
            IdentifierDetails::Did(_) => IdentifierType::Did,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DetailCredential {
    pub issuance_date: Option<OffsetDateTime>,
    pub valid_from: Option<OffsetDateTime>,
    pub valid_until: Option<OffsetDateTime>,
    pub update_at: Option<OffsetDateTime>,
    pub invalid_before: Option<OffsetDateTime>,
    pub issuer: IdentifierDetails,
    pub subject: Option<IdentifierDetails>,
    pub claims: HashMap<String, CredentialClaim>,
    pub status: Vec<CredentialStatus>,
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

/// Claims of the credential, nested by technical keys.
pub type IssuedClaims = IndexMap<String, IssuedClaimValue>;

/// Claim value resolved by its datatype
#[derive(Clone, Debug, PartialEq)]
pub enum IssuedClaimValue {
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    /// full-date or RFC 3339 date-time
    Date(String),
    /// data URI
    Picture(String),
    /// data URI, encoded as raw image bytes in mdoc (ISO 18013-5 portrait)
    MdlPortrait(String),
    /// data URI, SWIYU credentials strip the prefix
    SwiyuPicture(String),
    Object(IssuedClaims),
    Array(Vec<IssuedClaimValue>),
}

impl From<IssuedClaimValue> for serde_json::Value {
    fn from(claim: IssuedClaimValue) -> Self {
        match claim {
            IssuedClaimValue::Bool(value) => Self::Bool(value),
            IssuedClaimValue::Number(value) => Self::Number(value),
            IssuedClaimValue::String(value)
            | IssuedClaimValue::Date(value)
            | IssuedClaimValue::Picture(value)
            | IssuedClaimValue::MdlPortrait(value)
            | IssuedClaimValue::SwiyuPicture(value) => Self::String(value),
            IssuedClaimValue::Object(claims) => Self::Object(
                claims
                    .into_iter()
                    .map(|(key, value)| (key, value.into()))
                    .collect(),
            ),
            IssuedClaimValue::Array(values) => {
                Self::Array(values.into_iter().map(Into::into).collect())
            }
        }
    }
}

#[cfg(test)]
impl From<serde_json::Value> for IssuedClaimValue {
    fn from(value: serde_json::Value) -> Self {
        match value {
            serde_json::Value::Bool(value) => Self::Bool(value),
            serde_json::Value::Number(value) => Self::Number(value),
            serde_json::Value::String(value) => Self::String(value),
            serde_json::Value::Array(values) => {
                Self::Array(values.into_iter().map(Self::from).collect())
            }
            serde_json::Value::Object(_) => Self::Object(issued_claims(value)),
            serde_json::Value::Null => panic!("null is not an issued claim value"),
        }
    }
}

/// Builds test claims from JSON. JSON strings become string claims, date and picture claims need
/// to be built by hand.
#[cfg(test)]
pub(crate) fn issued_claims(value: serde_json::Value) -> IssuedClaims {
    let serde_json::Value::Object(claims) = value else {
        panic!("issued claims must be a JSON object");
    };
    claims
        .into_iter()
        .map(|(key, value)| (key, value.into()))
        .collect()
}

#[derive(Debug)]
pub struct CredentialData {
    pub credential: UnsignedCredential,
    pub holder_identifier: Option<Identifier>,
    pub holder_key_id: Option<String>,
    pub issuer_certificate: Option<Certificate>,
}

/// Format-specific content of a credential to be issued
#[derive(Debug)]
#[expect(clippy::large_enum_variant)]
pub enum UnsignedCredential {
    /// W3C VCDM based formats (JWT, SD-JWT, JSON-LD)
    Vcdm(VcdmCredential),
    Mdoc(MdocCredential),
    SdJwtVc(SdJwtVcCredential),
}

impl UnsignedCredential {
    pub fn into_vcdm(self) -> Result<VcdmCredential, FormatterError> {
        match self {
            Self::Vcdm(vcdm) => Ok(vcdm),
            _ => Err(FormatterError::CouldNotFormat(
                "Expected VCDM credential".to_string(),
            )),
        }
    }

    pub fn into_mdoc(self) -> Result<MdocCredential, FormatterError> {
        match self {
            Self::Mdoc(mdoc) => Ok(mdoc),
            _ => Err(FormatterError::CouldNotFormat(
                "Expected mdoc credential".to_string(),
            )),
        }
    }

    pub fn into_sd_jwt_vc(self) -> Result<SdJwtVcCredential, FormatterError> {
        match self {
            Self::SdJwtVc(sd_jwt_vc) => Ok(sd_jwt_vc),
            _ => Err(FormatterError::CouldNotFormat(
                "Expected SD-JWT VC credential".to_string(),
            )),
        }
    }
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
    pub transaction_data: Option<serde_json::Value>,
}

#[derive(Clone, Debug)]
pub struct CredentialPresentation {
    pub token: SerializedCredential,
    pub disclosed_keys: Vec<String>,
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
    /// custom schemaId can be specified by the user during creation
    SupportsSchemaId,
    RequiresPresentationEncryption,
    SupportsCombinedPresentation,
    SupportsTxCode,
    RequiresNamespaces,
    SupportsTransactionData,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SelectiveDisclosure {
    AnyLevel,
    FirstLevel,
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
        Ok(match self {
            Self::Object { id, .. } => id,
            Self::Url(url) => url,
        }
        .as_str()
        .parse()
        .map_err(DidMethodError::DidValueError)
        .error_while("parsing issuer DID")?)
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
