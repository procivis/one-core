use dto_mapper::convert_inner;
use sea_orm::{
    sea_query::{ConditionType, Expr, IntoCondition, IntoTableRef, Query, SimpleExpr},
    ActiveValue::Set,
    ColumnTrait, EntityTrait, IntoIdentity, IntoSimpleExpr, JoinType, QuerySelect, RelationDef,
    RelationType, Select,
};
use time::OffsetDateTime;

use one_core::{
    model::{
        history::{GetHistoryList, History, HistoryFilterValue, SortableHistoryColumn},
        list_filter::ListFilterCondition,
        list_query::ListQuery,
        organisation::Organisation,
    },
    repository::error::DataLayerError,
};

use crate::{
    common::calculate_pages_count,
    entity::{claim, credential, credential_schema, history, proof, proof_claim},
    list_query_generic::{
        get_equals_condition, get_greater_than_condition, get_lesser_than_condition,
        IntoFilterCondition, IntoSortingColumn,
    },
};

impl From<history::Model> for History {
    fn from(value: history::Model) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            action: value.action.into(),
            entity_id: value.entity_id,
            entity_type: value.entity_type.into(),
            organisation: Some(Organisation {
                id: value.organisation_id.into(),
                created_date: OffsetDateTime::UNIX_EPOCH,
                last_modified: OffsetDateTime::UNIX_EPOCH,
            }),
        }
    }
}

impl TryFrom<History> for history::ActiveModel {
    type Error = DataLayerError;

    fn try_from(value: History) -> Result<Self, Self::Error> {
        let organisation = value.organisation.ok_or(DataLayerError::MappingError)?;

        Ok(Self {
            id: Set(value.id),
            created_date: Set(value.created_date),
            action: Set(value.action.into()),
            entity_id: Set(value.entity_id),
            entity_type: Set(value.entity_type.into()),
            organisation_id: Set(organisation.id.into()),
        })
    }
}

impl IntoSortingColumn for SortableHistoryColumn {
    fn get_column(&self) -> SimpleExpr {
        match self {
            SortableHistoryColumn::CreatedDate => history::Column::CreatedDate,
            SortableHistoryColumn::Action => history::Column::Action,
            SortableHistoryColumn::EntityType => history::Column::EntityType,
        }
        .into_simple_expr()
    }
}

impl IntoFilterCondition for HistoryFilterValue {
    fn get_condition(self) -> sea_orm::Condition {
        match self {
            HistoryFilterValue::EntityType(entity_type) => get_equals_condition(
                history::Column::EntityType,
                history::HistoryEntityType::from(entity_type),
            ),
            HistoryFilterValue::EntityId(entity_id) => {
                get_equals_condition(history::Column::EntityId, entity_id)
            }
            HistoryFilterValue::Action(action) => get_equals_condition(
                history::Column::Action,
                history::HistoryAction::from(action),
            ),
            HistoryFilterValue::CreatedDateFrom(created_date_from) => {
                get_greater_than_condition(history::Column::CreatedDate, created_date_from)
            }
            HistoryFilterValue::CreatedDateTo(created_date_to) => {
                get_lesser_than_condition(history::Column::CreatedDate, created_date_to)
            }
            HistoryFilterValue::DidId(did_id) => credential::Column::IssuerDidId
                .eq(did_id)
                .or(credential::Column::HolderDidId.eq(did_id))
                .or(proof::Column::VerifierDidId.eq(did_id))
                .or(history::Column::EntityId
                    .eq(did_id)
                    .and(history::Column::EntityType.eq(history::HistoryEntityType::Did)))
                .into_condition(),
            HistoryFilterValue::CredentialId(credential_id) => history::Column::EntityId
                .eq(credential_id.to_string())
                .and(history::Column::EntityType.eq(history::HistoryEntityType::Credential))
                .or(history::Column::EntityId.in_subquery(
                    Query::select()
                        .expr(proof_claim::Column::ProofId.into_expr())
                        .from(proof_claim::Entity)
                        .inner_join(
                            claim::Entity,
                            Expr::col((proof_claim::Entity, proof_claim::Column::ClaimId))
                                .eq(Expr::col((claim::Entity, claim::Column::Id))),
                        )
                        .cond_where(claim::Column::CredentialId.eq(credential_id.to_string()))
                        .to_owned(),
                ))
                .into_condition(),
            HistoryFilterValue::CredentialSchemaId(credential_schema_id) => {
                history::Column::EntityId
                    .eq(credential_schema_id.to_string())
                    .and(
                        history::Column::EntityType
                            .eq(history::HistoryEntityType::CredentialSchema),
                    )
                    .or(history::Column::EntityId.in_subquery(
                        Query::select()
                            .expr(proof_claim::Column::ProofId.into_expr())
                            .from(proof_claim::Entity)
                            .inner_join(
                                claim::Entity,
                                Expr::col((proof_claim::Entity, proof_claim::Column::ClaimId))
                                    .eq(Expr::col((claim::Entity, claim::Column::Id))),
                            )
                            .inner_join(
                                credential::Entity,
                                Expr::col((claim::Entity, claim::Column::CredentialId))
                                    .eq(Expr::col((credential::Entity, credential::Column::Id))),
                            )
                            .inner_join(
                                credential_schema::Entity,
                                Expr::col((
                                    credential::Entity,
                                    credential::Column::CredentialSchemaId,
                                ))
                                .eq(Expr::col((
                                    credential_schema::Entity,
                                    credential_schema::Column::Id,
                                ))),
                            )
                            .cond_where(
                                credential_schema::Column::Id.eq(credential_schema_id.to_string()),
                            )
                            .to_owned(),
                    ))
                    .or(history::Column::EntityId.in_subquery(
                        Query::select()
                            .expr(credential::Column::Id.into_expr())
                            .from(credential::Entity)
                            .inner_join(
                                credential_schema::Entity,
                                Expr::col((
                                    credential::Entity,
                                    credential::Column::CredentialSchemaId,
                                ))
                                .eq(Expr::col((
                                    credential_schema::Entity,
                                    credential_schema::Column::Id,
                                ))),
                            )
                            .cond_where(
                                credential_schema::Column::Id.eq(credential_schema_id.to_string()),
                            )
                            .to_owned(),
                    ))
                    .into_condition()
            }
            HistoryFilterValue::OrganisationId(organisation_id) => {
                get_equals_condition(history::Column::OrganisationId, organisation_id.to_string())
            }
        }
    }
}

pub trait SelectWithFilterJoins<SortableColumn>
where
    SortableColumn: IntoSortingColumn,
{
    fn with_filter_joins(self, query: &ListQuery<SortableColumn, HistoryFilterValue>) -> Self;
}

impl<T, SortableColumn> SelectWithFilterJoins<SortableColumn> for Select<T>
where
    T: EntityTrait,
    SortableColumn: IntoSortingColumn,
{
    fn with_filter_joins(self, query: &ListQuery<SortableColumn, HistoryFilterValue>) -> Select<T> {
        let mut result = self;

        if let Some(filter) = &query.filtering {
            let relation_defs = filter_to_list_of_relation_defs(filter);
            for relation_def in relation_defs {
                result = result.join(JoinType::LeftJoin, relation_def);
            }
        }

        result
    }
}

fn filter_to_list_of_relation_defs(
    filter: &ListFilterCondition<HistoryFilterValue>,
) -> Vec<RelationDef> {
    let mut result = vec![];

    match filter {
        ListFilterCondition::Value(v) => {
            result.append(&mut history_filter_value_to_relation_def(v));
        }
        ListFilterCondition::And(filter_list) => {
            for value in filter_list {
                result.append(&mut filter_to_list_of_relation_defs(value));
            }
        }
        ListFilterCondition::Or(filter_list) => {
            for value in filter_list {
                result.append(&mut filter_to_list_of_relation_defs(value));
            }
        }
    }

    result
}

fn history_filter_value_to_relation_def(value: &HistoryFilterValue) -> Vec<RelationDef> {
    match value {
        HistoryFilterValue::DidId(_) => {
            vec![
                join_relation_def(history::Column::EntityId, credential::Column::Id),
                join_relation_def(history::Column::EntityId, proof::Column::Id),
            ]
        }
        _ => vec![],
    }
}

pub(crate) fn create_list_response(
    history_list: Vec<history::Model>,
    limit: Option<u64>,
    items_count: u64,
) -> GetHistoryList {
    GetHistoryList {
        values: convert_inner(history_list),
        total_pages: calculate_pages_count(items_count, limit.unwrap_or(0)),
        total_items: items_count,
    }
}

fn join_relation_def(
    from: impl ColumnTrait + IntoIdentity + Clone,
    to: impl ColumnTrait + IntoIdentity + Clone,
) -> RelationDef {
    RelationDef {
        rel_type: RelationType::HasMany,
        from_tbl: from.to_owned().entity_name().into_table_ref(),
        to_tbl: to.to_owned().entity_name().into_table_ref(),
        from_col: from.into_identity(),
        to_col: to.into_identity(),
        is_owner: false,
        on_delete: None,
        on_update: None,
        on_condition: None,
        fk_name: None,
        condition_type: ConditionType::Any,
    }
}
