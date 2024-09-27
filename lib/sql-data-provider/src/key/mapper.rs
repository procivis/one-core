use migration::SimpleExpr;
use one_core::model::key::{GetKeyList, Key, SortableKeyColumn};
use one_core::model::organisation::Organisation;
use one_dto_mapper::convert_inner;
use sea_orm::IntoSimpleExpr;

use crate::common::calculate_pages_count;
use crate::entity;
use crate::list_query::GetEntityColumn;

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

impl GetEntityColumn for SortableKeyColumn {
    fn get_simple_expr(&self) -> SimpleExpr {
        match self {
            SortableKeyColumn::Name => entity::key::Column::Name.into_simple_expr(),
            SortableKeyColumn::CreatedDate => entity::key::Column::CreatedDate.into_simple_expr(),
            SortableKeyColumn::PublicKey => entity::key::Column::PublicKey.into_simple_expr(),
            SortableKeyColumn::KeyType => entity::key::Column::KeyType.into_simple_expr(),
            SortableKeyColumn::StorageType => entity::key::Column::StorageType.into_simple_expr(),
        }
    }
}

pub(crate) fn create_list_response(
    keys: Vec<entity::key::Model>,
    limit: u64,
    items_count: u64,
) -> GetKeyList {
    GetKeyList {
        values: convert_inner(keys),
        total_pages: calculate_pages_count(items_count, limit),
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
