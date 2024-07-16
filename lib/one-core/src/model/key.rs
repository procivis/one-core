use crate::model::organisation::OrganisationRelations;

use crate::model::common::{GetListQueryParams, GetListResponse};
use one_providers::common_models::key::Key;

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
