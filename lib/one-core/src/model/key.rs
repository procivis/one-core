use shared_types::KeyId;
use time::OffsetDateTime;

use super::organisation::Organisation;
use crate::model::common::{GetListQueryParams, GetListResponse};
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

pub type GetKeyList = GetListResponse<Key>;
pub type GetKeyQuery = GetListQueryParams<SortableKeyColumn>;

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
    pub e: String,
    pub n: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyJwkOctData {
    pub r#use: Option<String>,
    pub k: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyJwkMlweData {
    pub r#use: Option<String>,
    pub alg: String,
    pub x: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyJwkEllipticData {
    pub r#use: Option<String>,
    pub crv: String,
    pub x: String,
    pub y: Option<String>,
}
