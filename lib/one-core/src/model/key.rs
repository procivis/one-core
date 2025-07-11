use std::str::FromStr;

use secrecy::SecretString;
use shared_types::{KeyId, OrganisationId};
use time::OffsetDateTime;

use super::list_filter::{ListFilterValue, StringMatch};
use super::list_query::ListQuery;
use super::organisation::Organisation;
use crate::config::core_config::KeyAlgorithmType;
use crate::model::common::GetListResponse;
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
    KeyType(String),
    KeyStorage(String),
    Ids(Vec<KeyId>),
    Remote(bool),
    RawPublicKey(Vec<u8>),
}

impl KeyFilterValue {
    pub fn remote(v: impl Into<bool>) -> Self {
        Self::Remote(v.into())
    }
}

impl ListFilterValue for KeyFilterValue {}

pub type KeyListQuery = ListQuery<SortableKeyColumn, KeyFilterValue>;

pub type GetKeyList = GetListResponse<Key>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKeyJwk {
    Ec(PublicKeyJwkEllipticData),
    Rsa(PublicKeyJwkRsaData),
    Okp(PublicKeyJwkEllipticData),
    Oct(PublicKeyJwkOctData),
    Mlwe(PublicKeyJwkMlweData),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyJwkRsaData {
    pub r#use: Option<String>,
    pub kid: Option<String>,
    pub e: String,
    pub n: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyJwkOctData {
    pub r#use: Option<String>,
    pub kid: Option<String>,
    pub k: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyJwkMlweData {
    pub r#use: Option<String>,
    pub kid: Option<String>,
    pub alg: String,
    pub x: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyJwkEllipticData {
    pub r#use: Option<String>,
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
    pub r#use: Option<String>,
    pub kid: Option<String>,
    pub alg: String,
    pub x: String,
    pub d: SecretString,
}

#[derive(Clone, Debug)]
pub struct PrivateKeyJwkEllipticData {
    pub r#use: Option<String>,
    pub kid: Option<String>,
    pub crv: String,
    pub x: String,
    pub y: Option<String>,
    pub d: SecretString,
}
