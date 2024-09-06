use dto_mapper::convert_inner;
use one_core::model::did::{Did, DidFilterValue, GetDidList, SortableDidColumn};
use one_core::repository::error::DataLayerError;
use sea_orm::sea_query::{IntoCondition, SimpleExpr};
use sea_orm::ActiveValue::NotSet;
use sea_orm::{ColumnTrait, IntoSimpleExpr, JoinType, RelationTrait, Set};

use crate::common::calculate_pages_count;
use crate::entity::{self, did, key, key_did};
use crate::list_query_generic::{
    get_equals_condition, get_string_match_condition, IntoFilterCondition, IntoJoinCondition,
    IntoSortingColumn, JoinRelation,
};

impl From<entity::did::Model> for Did {
    fn from(value: entity::did::Model) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            did: value.did,
            did_type: value.type_field.into(),
            did_method: value.method,
            organisation: None,
            keys: None,
            deactivated: value.deactivated,
        }
    }
}

impl IntoSortingColumn for SortableDidColumn {
    fn get_column(&self) -> SimpleExpr {
        match self {
            SortableDidColumn::Name => did::Column::Name,
            SortableDidColumn::CreatedDate => did::Column::CreatedDate,
            SortableDidColumn::Method => did::Column::Method,
            SortableDidColumn::Type => did::Column::TypeField,
            SortableDidColumn::Did => did::Column::Did,
            SortableDidColumn::Deactivated => did::Column::Deactivated,
        }
        .into_simple_expr()
    }
}

impl IntoFilterCondition for DidFilterValue {
    fn get_condition(self) -> sea_orm::Condition {
        match self {
            DidFilterValue::Name(string_match) => {
                get_string_match_condition(did::Column::Name, string_match)
            }
            DidFilterValue::Method(method) => get_equals_condition(did::Column::Method, method),
            DidFilterValue::Type(r#type) => {
                get_equals_condition(did::Column::TypeField, did::DidType::from(r#type))
            }
            DidFilterValue::Did(string_match) => {
                get_string_match_condition(did::Column::Did, string_match)
            }
            DidFilterValue::OrganisationId(organisation_id) => {
                get_equals_condition(did::Column::OrganisationId, organisation_id.to_string())
            }
            DidFilterValue::Deactivated(is_deactivated) => {
                get_equals_condition(did::Column::Deactivated, is_deactivated)
            }
            DidFilterValue::KeyAlgorithms(key_algorithms) => {
                key::Column::KeyType.is_in(key_algorithms).into_condition()
            }
            DidFilterValue::KeyStorages(key_storages) => key::Column::StorageType
                .is_in(key_storages)
                .into_condition(),
            DidFilterValue::KeyRoles(key_roles) => key_did::Column::Role
                .is_in(
                    key_roles
                        .into_iter()
                        .map(key_did::KeyRole::from)
                        .collect::<Vec<_>>(),
                )
                .into_condition(),
            DidFilterValue::DidMethods(methods) => {
                did::Column::Method.is_in(methods).into_condition()
            }
        }
    }
}

impl IntoJoinCondition for DidFilterValue {
    fn get_join(self) -> Vec<JoinRelation> {
        match self {
            DidFilterValue::KeyAlgorithms(_) => {
                vec![
                    JoinRelation {
                        join_type: JoinType::InnerJoin,
                        relation_def: did::Relation::KeyDid.def(),
                    },
                    JoinRelation {
                        join_type: JoinType::InnerJoin,
                        relation_def: key_did::Relation::Key.def(),
                    },
                ]
            }
            DidFilterValue::KeyRoles(_) => {
                vec![JoinRelation {
                    join_type: JoinType::InnerJoin,
                    relation_def: did::Relation::KeyDid.def(),
                }]
            }
            DidFilterValue::KeyStorages(_) => {
                vec![
                    JoinRelation {
                        join_type: JoinType::InnerJoin,
                        relation_def: did::Relation::KeyDid.def(),
                    },
                    JoinRelation {
                        join_type: JoinType::InnerJoin,
                        relation_def: key_did::Relation::Key.def(),
                    },
                ]
            }
            _ => vec![],
        }
    }
}

pub(crate) fn create_list_response(
    dids: Vec<did::Model>,
    limit: Option<u64>,
    items_count: u64,
) -> GetDidList {
    GetDidList {
        values: convert_inner(dids),
        total_pages: calculate_pages_count(items_count, limit.unwrap_or(0)),
        total_items: items_count,
    }
}

impl TryFrom<Did> for did::ActiveModel {
    type Error = DataLayerError;

    fn try_from(value: Did) -> Result<Self, Self::Error> {
        let organisation = value.organisation.ok_or(DataLayerError::MappingError)?;

        Ok(Self {
            id: Set(value.id),
            did: Set(value.did.to_owned()),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            name: Set(value.name),
            type_field: Set(value.did_type.into()),
            method: Set(value.did_method),
            organisation_id: Set(organisation.id),
            deactivated: Set(value.deactivated),
            deleted_at: NotSet,
        })
    }
}
