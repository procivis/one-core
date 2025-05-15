use one_core::model::key::{GetKeyList, Key, KeyFilterValue, SortableKeyColumn};
use one_core::model::organisation::Organisation;
use one_dto_mapper::convert_inner;
use sea_orm::sea_query::{IntoCondition, SimpleExpr};
use sea_orm::{ColumnTrait, IntoSimpleExpr};

use crate::common::calculate_pages_count;
use crate::entity;
use crate::list_query_generic::{
    IntoFilterCondition, IntoSortingColumn, get_equals_condition, get_string_match_condition,
};

pub(super) fn from_model_and_relations(
    value: entity::key::Model,
    organisation: Option<Organisation>,
) -> Key {
    Key {
        id: value.id,
        created_date: value.created_date,
        last_modified: value.last_modified,
        public_key: value.public_key,
        name: value.name,
        key_reference: value.key_reference,
        storage_type: value.storage_type,
        key_type: value.key_type,
        organisation: convert_inner(organisation),
    }
}

impl IntoSortingColumn for SortableKeyColumn {
    fn get_column(&self) -> SimpleExpr {
        match self {
            Self::Name => entity::key::Column::Name,
            Self::CreatedDate => entity::key::Column::CreatedDate,
            Self::PublicKey => entity::key::Column::PublicKey,
            Self::KeyType => entity::key::Column::KeyType,
            Self::StorageType => entity::key::Column::StorageType,
        }
        .into_simple_expr()
    }
}

impl IntoFilterCondition for KeyFilterValue {
    fn get_condition(self) -> sea_orm::Condition {
        match self {
            Self::Name(string_match) => {
                get_string_match_condition(entity::key::Column::Name, string_match)
            }
            Self::OrganisationId(organisation_id) => {
                get_equals_condition(entity::key::Column::OrganisationId, organisation_id)
            }
            Self::KeyType(r#type) => get_equals_condition(entity::key::Column::KeyType, r#type),
            Self::KeyStorage(storage) => {
                get_equals_condition(entity::key::Column::StorageType, storage)
            }
            Self::Ids(ids) => entity::key::Column::Id.is_in(ids).into_condition(),
        }
    }
}

pub(super) fn create_list_response(
    keys: Vec<entity::key::Model>,
    limit: Option<u64>,
    items_count: u64,
) -> GetKeyList {
    GetKeyList {
        values: convert_inner(keys),
        total_pages: calculate_pages_count(items_count, limit.unwrap_or(0)),
        total_items: items_count,
    }
}

impl From<entity::key::Model> for Key {
    fn from(value: entity::key::Model) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            public_key: value.public_key,
            name: value.name,
            key_reference: value.key_reference,
            storage_type: value.storage_type,
            key_type: value.key_type,
            organisation: None,
        }
    }
}
