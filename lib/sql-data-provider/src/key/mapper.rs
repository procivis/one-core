use one_core::model::key::{Key, KeyFilterValue, SortableKeyColumn};
use one_core::model::list_filter::ListFilterCondition;
use one_core::model::organisation::Organisation;
use one_dto_mapper::convert_inner;
use sea_orm::sea_query::{IntoCondition, SimpleExpr};
use sea_orm::{ColumnTrait, IntoSimpleExpr};

use crate::entity;
use crate::list_query_generic::{
    IntoFilterCondition, IntoSortingColumn, get_equals_condition, get_nullability_condition,
    get_string_match_condition,
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
    fn get_condition(self, _entire_filter: &ListFilterCondition<Self>) -> sea_orm::Condition {
        match self {
            Self::Name(string_match) => {
                get_string_match_condition(entity::key::Column::Name, string_match)
            }
            Self::OrganisationId(organisation_id) => {
                get_equals_condition(entity::key::Column::OrganisationId, organisation_id)
            }
            Self::KeyTypes(types) => entity::key::Column::KeyType.is_in(types).into_condition(),
            Self::KeyStorages(storages) => entity::key::Column::StorageType
                .is_in(storages)
                .into_condition(),
            Self::Ids(ids) => entity::key::Column::Id.is_in(ids).into_condition(),
            Self::Remote(is_remote) => {
                get_nullability_condition(entity::key::Column::KeyReference, is_remote)
            }
            Self::RawPublicKey(raw_public_key) => {
                get_equals_condition(entity::key::Column::PublicKey, raw_public_key)
            }
        }
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
