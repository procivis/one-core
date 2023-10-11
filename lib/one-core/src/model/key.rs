use crate::model::credential::{Credential, CredentialRelations};
use crate::model::did::{Did, DidRelations};
use crate::model::organisation::{Organisation, OrganisationRelations};
use time::OffsetDateTime;
use uuid::Uuid;

use super::common::{GetListQueryParams, GetListResponse};

pub type KeyId = Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelatedDid {
    pub role: KeyRole,
    pub did: Did,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Key {
    pub id: KeyId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub public_key: String,
    pub name: String,
    pub private_key: Vec<u8>,
    pub storage_type: String,
    pub key_type: String,

    // Relations:
    pub credential: Option<Credential>,
    pub dids: Option<Vec<RelatedDid>>,
    pub organisation: Option<Organisation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct KeyRelations {
    pub credential: Option<CredentialRelations>,
    pub dids: Option<DidRelations>,
    pub organisation: Option<OrganisationRelations>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyRole {
    Authentication,
    AssertionMethod,
    KeyAgreement,
    CapabilityInvocation,
    CapabilityDelegation,
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
