use std::str::FromStr;

use shared_types::{KeyId, OrganisationId};
use standardized_types::jwk::PrivateJwk;
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

pub trait PrivateJwkExt {
    fn supported_key_type(&self) -> KeyAlgorithmType;
}

impl PrivateJwkExt for PrivateJwk {
    fn supported_key_type(&self) -> KeyAlgorithmType {
        match self {
            PrivateJwk::Ec(_) => KeyAlgorithmType::Ecdsa,
            PrivateJwk::Okp(_) => KeyAlgorithmType::Eddsa,
            PrivateJwk::Mlwe(_) => KeyAlgorithmType::Dilithium,
        }
    }
}
