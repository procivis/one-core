use one_core::model::identifier::{Identifier, IdentifierFilterValue, SortableIdentifierColumn};
use one_core::model::list_filter::ListFilterCondition;
use one_core::model::organisation::Organisation;
use sea_orm::sea_query::{Alias, ColumnRef, ExprTrait, IntoCondition, IntoIden, SimpleExpr};
use sea_orm::{ColumnTrait, Condition, IntoSimpleExpr, JoinType, RelationTrait, Set};
use time::OffsetDateTime;

use crate::entity::identifier::ActiveModel;
use crate::entity::{self, certificate, did, identifier, key, key_did};
use crate::list_query_generic::{
    IntoFilterCondition, IntoJoinRelations, IntoSortingColumn, JoinRelation, get_equals_condition,
    get_string_match_condition,
};

impl From<Identifier> for ActiveModel {
    fn from(identifier: Identifier) -> Self {
        let organisation_id = identifier.organisation.map(|org| org.id);
        let did_id = identifier.did.map(|did| did.id);
        let key_id = identifier.key.map(|key| key.id);

        Self {
            id: Set(identifier.id),
            created_date: Set(identifier.created_date),
            last_modified: Set(identifier.last_modified),
            name: Set(identifier.name),
            r#type: Set(identifier.r#type.into()),
            is_remote: Set(identifier.is_remote),
            state: Set(identifier.state.into()),
            organisation_id: Set(organisation_id),
            did_id: Set(did_id),
            key_id: Set(key_id),
            deleted_at: Set(identifier.deleted_at),
        }
    }
}

impl From<entity::identifier::Model> for Identifier {
    fn from(value: entity::identifier::Model) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            r#type: value.r#type.into(),
            is_remote: value.is_remote,
            state: value.state.into(),
            deleted_at: value.deleted_at,
            organisation: value.organisation_id.map(|id| Organisation {
                id,
                name: "".to_string(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                deactivated_at: None,
            }),
            did: None,
            key: None,
            certificates: None,
        }
    }
}

impl IntoSortingColumn for SortableIdentifierColumn {
    fn get_column(&self) -> SimpleExpr {
        match self {
            SortableIdentifierColumn::Name => identifier::Column::Name,
            SortableIdentifierColumn::CreatedDate => identifier::Column::CreatedDate,
            SortableIdentifierColumn::Type => identifier::Column::Type,
            SortableIdentifierColumn::State => identifier::Column::State,
        }
        .into_simple_expr()
    }
}

impl IntoFilterCondition for IdentifierFilterValue {
    fn get_condition(self, _entire_filter: &ListFilterCondition<Self>) -> Condition {
        match self {
            IdentifierFilterValue::Ids(ids) => identifier::Column::Id.is_in(ids).into_condition(),
            IdentifierFilterValue::Name(string_match) => {
                get_string_match_condition(identifier::Column::Name, string_match)
            }
            IdentifierFilterValue::Types(types) => identifier::Column::Type
                .is_in(
                    types
                        .into_iter()
                        .map(identifier::IdentifierType::from)
                        .collect::<Vec<_>>(),
                )
                .into_condition(),
            IdentifierFilterValue::State(state) => get_equals_condition(
                identifier::Column::State,
                identifier::IdentifierState::from(state),
            ),
            IdentifierFilterValue::OrganisationId(organisation_id) => {
                get_equals_condition(identifier::Column::OrganisationId, organisation_id)
            }
            IdentifierFilterValue::DidMethods(did_methods) => entity::did::Column::Method
                .is_in(did_methods)
                .or(identifier::Column::Type.eq(identifier::IdentifierType::Certificate))
                .into_condition(),
            IdentifierFilterValue::IsRemote(is_remote) => identifier::Column::IsRemote
                .eq(is_remote)
                .or(identifier::Column::Type.eq(identifier::IdentifierType::Certificate))
                .into_condition(),
            IdentifierFilterValue::KeyAlgorithms(key_algorithms) => key::Column::KeyType
                .is_in(&key_algorithms)
                .or(ColumnRef::TableColumn(
                    Alias::new("did_key").into_iden(),
                    key::Column::KeyType.into_iden(),
                )
                .is_in(&key_algorithms))
                .or(ColumnRef::TableColumn(
                    Alias::new("certificate_key").into_iden(),
                    key::Column::KeyType.into_iden(),
                )
                .is_in(key_algorithms))
                .into_condition(),
            IdentifierFilterValue::KeyRoles(key_roles) => key_did::Column::Role
                .is_in(
                    key_roles
                        .into_iter()
                        .map(key_did::KeyRole::from)
                        .collect::<Vec<_>>(),
                )
                .or(identifier::Column::Type.ne(identifier::IdentifierType::Did))
                .into_condition(),
            IdentifierFilterValue::KeyStorages(key_storages) => key::Column::StorageType
                .is_in(&key_storages)
                .or(ColumnRef::TableColumn(
                    Alias::new("did_key").into_iden(),
                    key::Column::StorageType.into_iden(),
                )
                .is_in(&key_storages))
                .or(ColumnRef::TableColumn(
                    Alias::new("certificate_key").into_iden(),
                    key::Column::StorageType.into_iden(),
                )
                .is_in(key_storages))
                .into_condition(),
            IdentifierFilterValue::KeyIds(key_ids) => key::Column::Id
                .is_in(&key_ids)
                .or(ColumnRef::TableColumn(
                    Alias::new("did_key").into_iden(),
                    key::Column::Id.into_iden(),
                )
                .is_in(&key_ids))
                .or(ColumnRef::TableColumn(
                    Alias::new("certificate_key").into_iden(),
                    key::Column::Id.into_iden(),
                )
                .is_in(key_ids))
                .into_condition(),
        }
    }
}

impl IntoJoinRelations for IdentifierFilterValue {
    fn get_join(&self) -> Vec<JoinRelation> {
        match self {
            IdentifierFilterValue::DidMethods(_) => {
                vec![JoinRelation {
                    join_type: JoinType::LeftJoin,
                    relation_def: identifier::Relation::Did.def(),
                    alias: None,
                }]
            }
            IdentifierFilterValue::KeyRoles(_) => {
                vec![
                    JoinRelation {
                        join_type: JoinType::LeftJoin,
                        relation_def: identifier::Relation::Did.def(),
                        alias: None,
                    },
                    JoinRelation {
                        join_type: JoinType::LeftJoin,
                        relation_def: did::Relation::KeyDid.def(),
                        alias: None,
                    },
                ]
            }
            IdentifierFilterValue::KeyAlgorithms(_) | IdentifierFilterValue::KeyStorages(_) => {
                vec![
                    // IdentifierType::Did
                    JoinRelation {
                        join_type: JoinType::LeftJoin,
                        relation_def: identifier::Relation::Did.def(),
                        alias: None,
                    },
                    JoinRelation {
                        join_type: JoinType::LeftJoin,
                        relation_def: did::Relation::KeyDid.def(),
                        alias: None,
                    },
                    JoinRelation {
                        join_type: JoinType::LeftJoin,
                        relation_def: key_did::Relation::Key.def(),
                        alias: Some(Alias::new("did_key").into_iden()),
                    },
                    // IdentifierType::Key
                    JoinRelation {
                        join_type: JoinType::LeftJoin,
                        relation_def: identifier::Relation::Key.def(),
                        alias: None,
                    },
                    // IdentifierType::Certificate
                    JoinRelation {
                        join_type: JoinType::LeftJoin,
                        relation_def: identifier::Relation::Certificate.def(),
                        alias: None,
                    },
                    JoinRelation {
                        join_type: JoinType::LeftJoin,
                        relation_def: certificate::Relation::Key.def(),
                        alias: Some(Alias::new("certificate_key").into_iden()),
                    },
                ]
            }
            _ => vec![],
        }
    }
}
