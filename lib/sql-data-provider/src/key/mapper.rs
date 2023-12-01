use std::str::FromStr;
use uuid::Uuid;

use migration::SimpleExpr;
use sea_orm::IntoSimpleExpr;

use crate::entity;
use one_core::model::key::Key;
use one_core::model::key::{GetKeyList, SortableKeyColumn};
use one_core::model::organisation::Organisation;
use one_core::repository::error::DataLayerError;

use crate::{common::calculate_pages_count, list_query::GetEntityColumn};

pub(super) fn from_model_and_relations(
    value: entity::key::Model,
    organisation: Option<Organisation>,
) -> Result<Key, DataLayerError> {
    let id = Uuid::from_str(&value.id)?;

    Ok(Key {
        id,
        created_date: value.created_date,
        last_modified: value.last_modified,
        public_key: value.public_key,
        name: value.name,
        key_reference: value.key_reference,
        storage_type: value.storage_type,
        key_type: value.key_type,
        organisation,
    })
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
        values: keys
            .into_iter()
            .filter_map(|item| item.try_into().ok())
            .collect(),
        total_pages: calculate_pages_count(items_count, limit),
        total_items: items_count,
    }
}

impl TryFrom<entity::key::Model> for Key {
    type Error = DataLayerError;

    fn try_from(value: entity::key::Model) -> Result<Self, Self::Error> {
        let id = Uuid::from_str(&value.id)?;

        Ok(Self {
            id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            public_key: value.public_key,
            name: value.name,
            key_reference: value.key_reference,
            storage_type: value.storage_type,
            key_type: value.key_type,
            organisation: None,
        })
    }
}
