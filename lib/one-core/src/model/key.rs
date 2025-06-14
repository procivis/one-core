use std::str::FromStr;

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
    pub key_reference: Vec<u8>,
    pub storage_type: String,
    pub key_type: String,

    // Relations:
    pub organisation: Option<Organisation>,
}

impl Key {
    pub fn key_algorithm_type(&self) -> Option<KeyAlgorithmType> {
        KeyAlgorithmType::from_str(&self.key_type).ok()
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
