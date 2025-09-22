use std::str::FromStr;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use shared_types::{KeyId, OrganisationId};
use time::OffsetDateTime;

use super::list_filter::{ListFilterValue, StringMatch};
use super::list_query::ListQuery;
use super::organisation::Organisation;
use crate::config::core_config::KeyAlgorithmType;
use crate::model::common::GetListResponse;
use crate::model::list_filter::ValueComparison;
use crate::model::organisation::OrganisationRelations;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Key {
    pub id: KeyId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub public_key: Vec<u8>,
    pub name: String,
    pub key_reference: Option<Vec<u8>>,
    pub storage_type: String,
    pub key_type: String,

    // Relations:
    pub organisation: Option<Organisation>,
}

impl Key {
    pub fn key_algorithm_type(&self) -> Option<KeyAlgorithmType> {
        KeyAlgorithmType::from_str(&self.key_type).ok()
    }

    pub fn is_remote(&self) -> bool {
        self.key_reference.is_none()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct KeyRelations {
    pub organisation: Option<OrganisationRelations>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableKeyColumn {
    Name,
    CreatedDate,
    PublicKey,
    KeyType,
    StorageType,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyFilterValue {
    Name(StringMatch),
    OrganisationId(OrganisationId),
    KeyTypes(Vec<String>),
    KeyStorages(Vec<String>),
    Ids(Vec<KeyId>),
    Remote(bool),
    RawPublicKey(Vec<u8>),
    CreatedDate(ValueComparison<OffsetDateTime>),
    LastModified(ValueComparison<OffsetDateTime>),
}

impl KeyFilterValue {
    pub fn remote(v: impl Into<bool>) -> Self {
        Self::Remote(v.into())
    }
}

impl ListFilterValue for KeyFilterValue {}

pub type KeyListQuery = ListQuery<SortableKeyColumn, KeyFilterValue>;

pub type GetKeyList = GetListResponse<Key>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kty", rename_all = "UPPERCASE")]
pub enum PublicKeyJwk {
    Ec(PublicKeyJwkEllipticData),
    Rsa(PublicKeyJwkRsaData),
    Okp(PublicKeyJwkEllipticData),
    #[serde(rename = "oct")]
    Oct(PublicKeyJwkOctData),
    Mlwe(PublicKeyJwkMlweData),
}

impl PublicKeyJwk {
    pub fn kid(&self) -> Option<&str> {
        match self {
            PublicKeyJwk::Okp(data) | PublicKeyJwk::Ec(data) => data.kid.as_deref(),
            PublicKeyJwk::Oct(data) => data.kid.as_deref(),
            PublicKeyJwk::Mlwe(data) => data.kid.as_deref(),
            PublicKeyJwk::Rsa(data) => data.kid.as_deref(),
        }
    }
}

/// see: <https://datatracker.ietf.org/doc/html/rfc7517#section-4.2>
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum JwkUse {
    #[serde(rename = "sig")]
    Signature,
    #[serde(rename = "enc")]
    Encryption,
    #[serde(untagged)]
    Unknown(String),
}

impl From<String> for JwkUse {
    fn from(value: String) -> Self {
        match value.as_str() {
            "sig" => Self::Signature,
            "enc" => Self::Encryption,
            _ => Self::Unknown(value),
        }
    }
}

impl From<JwkUse> for String {
    fn from(value: JwkUse) -> Self {
        match value {
            JwkUse::Signature => "sig".to_string(),
            JwkUse::Encryption => "enc".to_string(),
            JwkUse::Unknown(value) => value,
        }
    }
}

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyJwkRsaData {
    pub alg: Option<String>,
    pub r#use: Option<JwkUse>,
    pub kid: Option<String>,
    pub e: String,
    pub n: String,
}

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyJwkOctData {
    pub alg: Option<String>,
    pub r#use: Option<JwkUse>,
    pub kid: Option<String>,
    pub k: String,
}

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyJwkMlweData {
    pub r#use: Option<JwkUse>,
    pub kid: Option<String>,
    pub alg: Option<String>,
    pub x: String,
}

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyJwkEllipticData {
    pub alg: Option<String>,
    pub r#use: Option<JwkUse>,
    pub kid: Option<String>,
    pub crv: String,
    pub x: String,
    pub y: Option<String>,
}

#[derive(Clone, Debug)]
pub enum PrivateKeyJwk {
    Ec(PrivateKeyJwkEllipticData),
    Okp(PrivateKeyJwkEllipticData),
    Mlwe(PrivateKeyJwkMlweData),
}

impl PrivateKeyJwk {
    pub fn supported_key_type(&self) -> KeyAlgorithmType {
        match self {
            PrivateKeyJwk::Ec(_) => KeyAlgorithmType::Ecdsa,
            PrivateKeyJwk::Okp(_) => KeyAlgorithmType::Eddsa,
            PrivateKeyJwk::Mlwe(_) => KeyAlgorithmType::Dilithium,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PrivateKeyJwkMlweData {
    pub r#use: Option<JwkUse>,
    pub kid: Option<String>,
    pub alg: String,
    pub x: String,
    pub d: SecretString,
}

#[derive(Clone, Debug)]
pub struct PrivateKeyJwkEllipticData {
    pub r#use: Option<JwkUse>,
    pub kid: Option<String>,
    pub crv: String,
    pub x: String,
    pub y: Option<String>,
    pub d: SecretString,
}
