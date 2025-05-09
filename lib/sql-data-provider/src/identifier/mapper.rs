use one_core::model::identifier::{Identifier, IdentifierFilterValue, SortableIdentifierColumn};
use one_core::model::organisation::Organisation;
use sea_orm::sea_query::{IntoCondition, SimpleExpr};
use sea_orm::{ColumnTrait, Condition, IntoSimpleExpr, JoinType, RelationTrait, Set};
use time::OffsetDateTime;

use crate::entity::identifier::ActiveModel;
use crate::entity::{self, did, identifier, key, key_did};
use crate::list_query_generic::{
    get_equals_condition, get_string_match_condition, IntoFilterCondition, IntoJoinRelations,
    IntoSortingColumn, JoinRelation,
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
            status: Set(identifier.status.into()),
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
            status: value.status.into(),
            deleted_at: value.deleted_at,
            organisation: value.organisation_id.map(|id| Organisation {
                id,
                name: "".to_string(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
            }),
            did: None,
            key: None,
        }
    }
}

impl IntoSortingColumn for SortableIdentifierColumn {
    fn get_column(&self) -> SimpleExpr {
        match self {
            SortableIdentifierColumn::Name => identifier::Column::Name,
            SortableIdentifierColumn::CreatedDate => identifier::Column::CreatedDate,
            SortableIdentifierColumn::Type => identifier::Column::Type,
            SortableIdentifierColumn::Status => identifier::Column::Status,
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
            IdentifierFilterValue::Status(status) => get_equals_condition(
                identifier::Column::Status,
                identifier::IdentifierStatus::from(status),
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
            IdentifierFilterValue::KeyAlgorithms(key_algorithms) => {
                key::Column::KeyType.is_in(key_algorithms).into_condition()
            }
            IdentifierFilterValue::KeyRoles(key_roles) => key_did::Column::Role
                .is_in(
                    key_roles
                        .into_iter()
                        .map(key_did::KeyRole::from)
                        .collect::<Vec<_>>(),
                )
                .into_condition(),
            IdentifierFilterValue::KeyStorages(key_storages) => key::Column::StorageType
                .is_in(key_storages)
                .into_condition(),
        }
    }
}

impl IntoJoinRelations for IdentifierFilterValue {
    fn get_join(&self) -> Vec<JoinRelation> {
        // TODO(CUSTODY-5750): these join relations and filtering are only correct for Identifiers
        // of did type
        match self {
            IdentifierFilterValue::DidMethods(_)
            | IdentifierFilterValue::KeyAlgorithms(_)
            | IdentifierFilterValue::KeyStorages(_)
            | IdentifierFilterValue::KeyRoles(_) => {
                vec![
                    JoinRelation {
                        join_type: JoinType::InnerJoin,
                        relation_def: identifier::Relation::Did.def(),
                    },
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
