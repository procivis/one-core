use one_core::model::did::{Did, DidFilterValue, SortableDidColumn};
use one_core::model::list_filter::ListFilterCondition;
use one_core::repository::error::DataLayerError;
use sea_orm::ActiveValue::NotSet;
use sea_orm::sea_query::{IntoCondition, SimpleExpr};
use sea_orm::{ColumnTrait, IntoSimpleExpr, JoinType, RelationTrait, Set};

use crate::entity::{self, did, key, key_did};
use crate::list_query_generic::{
    IntoFilterCondition, IntoJoinRelations, IntoSortingColumn, JoinRelation, get_equals_condition,
    get_string_match_condition,
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
            log: value.log,
        }
    }
}

impl IntoSortingColumn for SortableDidColumn {
    fn get_column(&self) -> SimpleExpr {
        match self {
            Self::Name => did::Column::Name,
            Self::CreatedDate => did::Column::CreatedDate,
            Self::Method => did::Column::Method,
            Self::Type => did::Column::TypeField,
            Self::Did => did::Column::Did,
            Self::Deactivated => did::Column::Deactivated,
        }
        .into_simple_expr()
    }
}

impl IntoFilterCondition for DidFilterValue {
    fn get_condition(self, _entire_filter: &ListFilterCondition<Self>) -> sea_orm::Condition {
        match self {
            Self::Name(string_match) => get_string_match_condition(did::Column::Name, string_match),
            Self::Method(method) => get_equals_condition(did::Column::Method, method),
            Self::Type(r#type) => {
                get_equals_condition(did::Column::TypeField, did::DidType::from(r#type))
            }
            Self::Did(string_match) => get_string_match_condition(did::Column::Did, string_match),
            Self::OrganisationId(organisation_id) => {
                get_equals_condition(did::Column::OrganisationId, organisation_id.to_string())
            }
            Self::Deactivated(is_deactivated) => {
                get_equals_condition(did::Column::Deactivated, is_deactivated)
            }
            Self::KeyAlgorithms(key_algorithms) => {
                key::Column::KeyType.is_in(key_algorithms).into_condition()
            }
            Self::KeyStorages(key_storages) => key::Column::StorageType
                .is_in(key_storages)
                .into_condition(),
            Self::KeyRoles(key_roles) => key_did::Column::Role
                .is_in(
                    key_roles
                        .into_iter()
                        .map(key_did::KeyRole::from)
                        .collect::<Vec<_>>(),
                )
                .into_condition(),
            Self::KeyIds(key_ids) => key_did::Column::KeyId.is_in(key_ids).into_condition(),
            Self::DidMethods(methods) => did::Column::Method.is_in(methods).into_condition(),
        }
    }
}

impl IntoJoinRelations for DidFilterValue {
    fn get_join(&self) -> Vec<JoinRelation> {
        match self {
            Self::KeyAlgorithms(_) | Self::KeyStorages(_) => {
                vec![
                    JoinRelation {
                        join_type: JoinType::InnerJoin,
                        relation_def: did::Relation::KeyDid.def(),
                        alias: None,
                    },
                    JoinRelation {
                        join_type: JoinType::InnerJoin,
                        relation_def: key_did::Relation::Key.def(),
                        alias: None,
                    },
                ]
            }
            Self::KeyRoles(_) | Self::KeyIds(_) => {
                vec![JoinRelation {
                    join_type: JoinType::InnerJoin,
                    relation_def: did::Relation::KeyDid.def(),
                    alias: None,
                }]
            }
            _ => vec![],
        }
    }
}

impl TryFrom<Did> for did::ActiveModel {
    type Error = DataLayerError;

    fn try_from(value: Did) -> Result<Self, Self::Error> {
        let organisation_id = value.organisation.map(|f| f.id);

        Ok(Self {
            id: Set(value.id),
            did: Set(value.did.to_owned()),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            name: Set(value.name),
            type_field: Set(value.did_type.into()),
            method: Set(value.did_method),
            organisation_id: Set(organisation_id),
            deactivated: Set(value.deactivated),
            deleted_at: NotSet,
            log: Set(value.log),
        })
    }
}
