use std::collections::HashMap;
use std::sync::Arc;

use one_core::model::did::{Did, DidFilterValue, RelatedKey, SortableDidColumn};
use one_core::model::key::Key;
use one_core::model::list_filter::ListFilterCondition;
use one_core::model::relation::{AsyncVecLoader, Related, RelatedVec};
use one_core::repository::error::DataLayerError;
use one_core::repository::key_repository::KeyRepository;
use one_core::repository::organisation_repository::OrganisationRepository;
use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::{ColumnRef, IntoCondition};
use sea_orm::{ColumnTrait, EntityTrait, JoinType, QueryFilter, RelationTrait};
use shared_types::{DidId, KeyId};

use crate::entity::{did, key, key_did};
use crate::list_query_generic::{
    ColumnSortingBehavior, IntoFilterCondition, IntoJoinRelations, IntoSortingColumn, JoinRelation,
    get_equals_condition, get_string_match_condition,
};
use crate::transaction_context::TransactionManagerImpl;

impl IntoSortingColumn for SortableDidColumn {
    fn get_column(&self) -> (ColumnRef, ColumnSortingBehavior) {
        match self {
            Self::Name => ColumnSortingBehavior::case_insensitive(did::Column::Name),
            Self::CreatedDate => ColumnSortingBehavior::default(did::Column::CreatedDate),
            Self::Method => ColumnSortingBehavior::default(did::Column::Method),
            Self::Type => ColumnSortingBehavior::default(did::Column::TypeField),
            Self::Did => ColumnSortingBehavior::case_insensitive(did::Column::Did),
            Self::Deactivated => ColumnSortingBehavior::default(did::Column::Deactivated),
        }
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

impl From<Did> for did::ActiveModel {
    fn from(value: Did) -> Self {
        Self {
            id: Set(value.id),
            did: Set(value.did.to_owned()),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            name: Set(value.name),
            type_field: Set(value.did_type.into()),
            method: Set(value.did_method),
            organisation_id: Set(value.organisation.id()),
            deactivated: Set(value.deactivated),
            deleted_at: Set(value.deleted_at),
            log: Set(value.log),
        }
    }
}

pub(crate) fn did_from_model(
    model: did::Model,
    db: &TransactionManagerImpl,
    organisation_repository: &Arc<dyn OrganisationRepository>,
    key_repository: &Arc<dyn KeyRepository>,
) -> Did {
    let id = model.id;
    Did {
        id,
        created_date: model.created_date,
        last_modified: model.last_modified,
        deleted_at: model.deleted_at,
        name: model.name,
        did: model.did,
        did_type: model.type_field.into(),
        did_method: model.method,
        organisation: Related::new(model.organisation_id, organisation_repository.to_owned()),
        keys: RelatedVec::new(DidKeysLoader {
            id,
            db: db.clone(),
            key_repository: key_repository.to_owned(),
        }),
        deactivated: model.deactivated,
        log: model.log,
    }
}

struct DidKeysLoader {
    pub id: DidId,
    pub db: TransactionManagerImpl,
    pub key_repository: Arc<dyn KeyRepository>,
}

#[async_trait::async_trait]
impl AsyncVecLoader<RelatedKey> for DidKeysLoader {
    async fn load(&self) -> Result<Vec<RelatedKey>, DataLayerError> {
        let key_dids = key_did::Entity::find()
            .filter(key_did::Column::DidId.eq(self.id))
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        let mut related_keys: Vec<RelatedKey> = vec![];
        let mut key_map: HashMap<KeyId, Key> = HashMap::default();
        for key_did_model in key_dids {
            let key_id = &key_did_model.key_id;
            let key = if let Some(key) = key_map.get(key_id) {
                key.to_owned()
            } else {
                let key = self.key_repository.get_key(key_id).await?;

                key_map.insert(*key_id, key.to_owned());
                key
            };

            related_keys.push(RelatedKey {
                role: key_did_model.role.into(),
                key,
                reference: key_did_model.reference,
            })
        }

        Ok(related_keys)
    }
}
