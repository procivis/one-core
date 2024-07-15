use crate::model::organisation::{Organisation, OrganisationRelations};
use dto_mapper::{convert_inner, From, Into};
use shared_types::KeyId;
use time::OffsetDateTime;

use super::common::{GetListQueryParams, GetListResponse};

#[derive(Clone, Debug, Eq, PartialEq, From, Into)]
#[from(one_providers::common_models::key::Key)]
#[into(one_providers::common_models::key::Key)]
pub struct Key {
    pub id: KeyId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    #[into(with_fn = convert_inner)]
    #[from(with_fn = convert_inner)]
    pub public_key: Vec<u8>,
    pub name: String,
    #[into(with_fn = convert_inner)]
    #[from(with_fn = convert_inner)]
    pub key_reference: Vec<u8>,
    pub storage_type: String,
    pub key_type: String,

    // Relations:
    #[into(with_fn = convert_inner)]
    #[from(with_fn = convert_inner)]
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
