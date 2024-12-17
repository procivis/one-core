//! Methods for signing and verifying credentials, as well as `struct`s and `enum`s.

use std::collections::HashMap;
use std::fmt::{Display, Formatter};

use async_trait::async_trait;
use indexmap::IndexMap;
use one_crypto::SignerError;
use serde::{Deserialize, Serialize};
use shared_types::DidValue;
use strum::{Display, IntoStaticStr};
use time::{Duration, OffsetDateTime};
use url::Url;

use super::error::FormatterError;
use super::json_ld::model::{Evidence, RelatedResource, TermsOfUse};
use crate::model::credential_schema::{LayoutProperties, LayoutType};

pub type AuthenticationFn = Box<dyn SignatureProvider>;
pub type VerificationFn = Box<dyn TokenVerifier>;

/// Method for verifying credential.
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub trait TokenVerifier: Send + Sync {
    async fn verify<'a>(
        &self,
        issuer_did_value: Option<DidValue>,
        issuer_key_id: Option<&'a str>,
        algorithm: &'a str,
        token: &'a [u8],
        signature: &'a [u8],
    ) -> Result<(), SignerError>;
}

/// Method for signing credential with private key without exposing it.
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub trait SignatureProvider: Send + Sync {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError>;
    fn get_key_id(&self) -> Option<String>;
    fn get_key_type(&self) -> &str;
    fn get_public_key(&self) -> Vec<u8>;
}

#[derive(Debug, Clone)]
pub struct DetailCredential {
    pub id: Option<String>,
    pub valid_from: Option<OffsetDateTime>,
    pub valid_until: Option<OffsetDateTime>,
    pub update_at: Option<OffsetDateTime>,
    pub invalid_before: Option<OffsetDateTime>,
    pub issuer_did: Option<DidValue>,
    pub subject: Option<DidValue>,
    pub claims: CredentialSubject,
    pub status: Vec<CredentialStatus>,
    pub credential_schema: Option<CredentialSchema>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSubject {
    #[serde(flatten)]
    pub values: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchema {
    pub id: String,
    pub r#type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
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
            Self::Bool(value) => write!(f, "{}", value),
            Self::Float(value) => write!(f, "{}", value),
            Self::Integer(value) => write!(f, "{}", value),
            Self::String(value) => write!(f, "{}", value),
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
    pub id: Option<String>,
    pub issuance_date: OffsetDateTime,
    pub valid_for: Duration,
    pub claims: Vec<PublishedClaim>,
    pub issuer_did: Issuer,
    pub status: Vec<CredentialStatus>,
    pub schema: CredentialSchemaData,
    pub name: Option<Name>,
    pub description: Option<Description>,
    pub terms_of_use: Vec<TermsOfUse>,
    pub evidence: Vec<Evidence>,
    pub related_resource: Option<Vec<RelatedResource>>,
}

#[derive(Debug)]
pub struct CredentialSchemaData {
    pub id: Option<String>,
    pub r#type: Option<String>,
    pub context: Option<String>,
    pub name: String,
    pub metadata: Option<CredentialSchemaMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialStatus {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Url>,
    pub r#type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_purpose: Option<String>,
    #[serde(flatten)]
    pub additional_fields: HashMap<String, serde_json::Value>,
}

#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct FormatPresentationCtx {
    pub nonce: Option<String>,
    pub token_formats: Option<Vec<String>>,
    pub vc_format_map: HashMap<String, String>,
    pub mdoc_session_transcript: Option<Vec<u8>>,
}

#[allow(dead_code)]
#[derive(Debug, Default, Clone)]
pub struct ExtractPresentationCtx {
    pub nonce: Option<String>,
    pub format_nonce: Option<String>,
    pub issuance_date: Option<OffsetDateTime>,
    pub expiration_date: Option<OffsetDateTime>,
    pub mdoc_session_transcript: Option<Vec<u8>>,
    pub client_id: Option<String>,
    pub response_uri: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Presentation {
    pub id: Option<String>,
    pub issued_at: Option<OffsetDateTime>,
    pub expires_at: Option<OffsetDateTime>,
    pub issuer_did: Option<DidValue>,
    pub nonce: Option<String>,
    pub credentials: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
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
    pub issuance_did_methods: Vec<String>,
    pub issuance_exchange_protocols: Vec<String>,
    pub proof_exchange_protocols: Vec<String>,
    pub revocation_methods: Vec<String>,
    pub signing_key_algorithms: Vec<String>,
    pub verification_key_algorithms: Vec<String>,
    pub verification_key_storages: Vec<String>,
    pub datatypes: Vec<String>,
    pub allowed_schema_ids: Vec<String>,
    pub forbidden_claim_names: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Features {
    SelectiveDisclosure,
    SupportsCredentialDesign,
    RequiresSchemaId,
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
        Url::parse(self.into()).expect("Context is always a URL")
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum Issuer {
    Url(Url),
    Object {
        id: Url,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<Name>,
        #[serde(flatten)]
        rest: Option<IndexMap<String, serde_json::Value>>,
    },
}

impl Issuer {
    pub fn to_did_value(&self) -> DidValue {
        match self {
            Self::Object { id, .. } => id.to_string().into(),
            Self::Url(url) => url.to_string().into(),
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
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct LanguageValue {
    #[serde(rename = "@value")]
    value: String,
    #[serde(default, rename = "@language", skip_serializing_if = "Option::is_none")]
    language: Option<String>,
    #[serde(
        default,
        rename = "@direction",
        skip_serializing_if = "Option::is_none"
    )]
    direction: Option<String>,
}
