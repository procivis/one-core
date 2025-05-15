use one_core::model::identifier::{Identifier, IdentifierFilterValue, SortableIdentifierColumn};
use one_core::model::organisation::Organisation;
use sea_orm::sea_query::{Alias, ColumnRef, ExprTrait, IntoCondition, IntoIden, SimpleExpr};
use sea_orm::{ColumnTrait, Condition, IntoSimpleExpr, JoinType, RelationTrait, Set};
use time::OffsetDateTime;

use crate::entity::identifier::ActiveModel;
use crate::entity::{self, did, identifier, key, key_did};
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
    fn get_condition(self) -> Condition {
        match self {
            IdentifierFilterValue::Ids(ids) => identifier::Column::Id.is_in(ids).into_condition(),
            IdentifierFilterValue::Name(string_match) => {
                get_string_match_condition(identifier::Column::Name, string_match)
            }
            IdentifierFilterValue::Type(r#type) => get_equals_condition(
                identifier::Column::Type,
                identifier::IdentifierType::from(r#type),
            ),
            IdentifierFilterValue::State(state) => get_equals_condition(
                identifier::Column::State,
                identifier::IdentifierState::from(state),
            ),
            IdentifierFilterValue::OrganisationId(organisation_id) => {
                get_equals_condition(identifier::Column::OrganisationId, organisation_id)
            }
            IdentifierFilterValue::DidMethods(did_methods) => entity::did::Column::Method
                .is_in(did_methods)
                .into_condition(),
            IdentifierFilterValue::IsRemote(is_remote) => {
                get_equals_condition(identifier::Column::IsRemote, is_remote)
            }
            IdentifierFilterValue::KeyAlgorithms(key_algorithms) => key::Column::KeyType
                .is_in(key_algorithms.clone())
                .or(ColumnRef::TableColumn(
                    Alias::new("did_key").into_iden(),
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
                .into_condition(),
            IdentifierFilterValue::KeyStorages(key_storages) => key::Column::StorageType
                .is_in(key_storages.clone())
                .or(ColumnRef::TableColumn(
                    Alias::new("did_key").into_iden(),
                    key::Column::StorageType.into_iden(),
                )
                .is_in(key_storages))
                .into_condition(),
        }
    }
}

impl IntoJoinRelations for IdentifierFilterValue {
    fn get_join(&self) -> Vec<JoinRelation> {
        match self {
            IdentifierFilterValue::DidMethods(_)
            | IdentifierFilterValue::KeyAlgorithms(_)
            | IdentifierFilterValue::KeyStorages(_)
            | IdentifierFilterValue::KeyRoles(_) => {
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
                    JoinRelation {
                        join_type: JoinType::LeftJoin,
                        relation_def: key_did::Relation::Key.def(),
                        alias: Some(Alias::new("did_key").into_iden()),
                    },
                    JoinRelation {
                        join_type: JoinType::LeftJoin,
                        relation_def: identifier::Relation::Key.def(),
                        alias: None,
                    },
                ]
            }
            _ => vec![],
        }
    }
}
