use crate::mapper::order_from_sort_direction;
use one_core::model::{
    common::SortDirection,
    list_filter::{
        ComparisonType, ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
        ValueComparison,
    },
    list_query::ListQuery,
};
use sea_orm::{
    query::*,
    sea_query::{IntoCondition, SimpleExpr},
    ColumnTrait, EntityTrait, QueryOrder, QuerySelect, RelationDef,
};

pub trait IntoSortingColumn {
    /// converts declared sorting column into a sea-orm column
    fn get_column(&self) -> SimpleExpr;
}

pub trait IntoFilterCondition: Clone + ListFilterValue {
    /// converts single query field into a sea-orm condition
    fn get_condition(self) -> Condition;
}

pub struct JoinRelation {
    pub join_type: JoinType,
    pub relation_def: RelationDef,
}

pub trait IntoJoinCondition: Clone + ListFilterValue {
    fn get_join(self) -> Vec<JoinRelation>;
}

pub trait SelectWithFilterJoin<SortableColumn, JoinValue>
where
    SortableColumn: IntoSortingColumn,
    JoinValue: IntoJoinCondition,
{
    /// applies all `query` declared constraits (Joining, sorting and pagination) on the query
    fn with_filter_join(self, query: &ListQuery<SortableColumn, JoinValue>) -> Self;
}

impl<T, SortableColumn, JoinValue> SelectWithFilterJoin<SortableColumn, JoinValue> for Select<T>
where
    T: EntityTrait,
    SortableColumn: IntoSortingColumn,
    JoinValue: IntoJoinCondition,
{
    fn with_filter_join(self, query: &ListQuery<SortableColumn, JoinValue>) -> Select<T> {
        let mut result = self;

        if let Some(filter) = &query.filtering {
            let mut unique_relations: Vec<JoinRelation> = vec![];
            for relation in get_join_condition(filter) {
                if !unique_relations.iter().any(|r| {
                    r.join_type == relation.join_type
                        && r.relation_def.to_tbl == relation.relation_def.to_tbl
                        && r.relation_def.from_tbl == relation.relation_def.from_tbl
                }) {
                    unique_relations.push(relation);
                }
            }

            for JoinRelation {
                join_type,
                relation_def,
            } in unique_relations
            {
                result = result.join(join_type, relation_def);
            }
        }

        result
    }
}

// helpers
fn get_join_condition<JoinValue: IntoJoinCondition>(
    filter: &ListFilterCondition<JoinValue>,
) -> Vec<JoinRelation> {
    let mut result = vec![];
    match filter {
        ListFilterCondition::Value(v) => {
            result.append(&mut v.to_owned().get_join());
        }
        ListFilterCondition::And(filter_list) => {
            for value in filter_list {
                result.append(&mut get_join_condition(value));
            }
        }
        ListFilterCondition::Or(filter_list) => {
            for value in filter_list {
                result.append(&mut get_join_condition(value));
            }
        }
    }

    result
}

pub trait SelectWithListQuery<SortableColumn, FilterValue>
where
    SortableColumn: IntoSortingColumn,
    FilterValue: IntoFilterCondition,
{
    /// applies all `query` declared constraits (filtering, sorting and pagination) on the query
    fn with_list_query(self, query: &ListQuery<SortableColumn, FilterValue>) -> Self;
}

impl<T, SortableColumn, FilterValue> SelectWithListQuery<SortableColumn, FilterValue> for Select<T>
where
    T: EntityTrait,
    SortableColumn: IntoSortingColumn,
    FilterValue: IntoFilterCondition,
{
    fn with_list_query(self, query: &ListQuery<SortableColumn, FilterValue>) -> Select<T> {
        let mut result = self;

        if let Some(filter) = &query.filtering {
            if !is_condition_empty(filter) {
                result = result.filter(get_filter_condition(filter));
            }
        }

        if let Some(sorting) = &query.sorting {
            result = result.order_by(
                sorting.column.get_column(),
                order_from_sort_direction(sorting.direction.unwrap_or(SortDirection::Ascending)),
            );
        }

        if let Some(pagination) = &query.pagination {
            let limit = pagination.page_size as u64;
            let offset = (pagination.page as u64) * limit;
            result = result.offset(offset).limit(limit)
        }

        result
    }
}

// helpers
fn get_filter_condition<FilterValue: IntoFilterCondition>(
    filter_condition: &ListFilterCondition<FilterValue>,
) -> Condition {
    match filter_condition {
        ListFilterCondition::And(conditions) => {
            let mut result = Condition::all();
            for condition in conditions {
                if !is_condition_empty(condition) {
                    result = result.add(get_filter_condition(condition));
                }
            }
            result
        }
        ListFilterCondition::Or(conditions) => {
            let mut result = Condition::any();
            for condition in conditions {
                if !is_condition_empty(condition) {
                    result = result.add(get_filter_condition(condition));
                }
            }
            result
        }
        ListFilterCondition::Value(value) => value.to_owned().get_condition(),
    }
}

fn is_condition_empty<FilterValue: IntoFilterCondition>(
    filter_condition: &ListFilterCondition<FilterValue>,
) -> bool {
    match filter_condition {
        ListFilterCondition::And(conditions) => conditions.is_empty(),
        ListFilterCondition::Or(conditions) => conditions.is_empty(),
        ListFilterCondition::Value { .. } => false,
    }
}

/// helper function to construct a `sea_query::Condition` from a `StringMatch`
pub(crate) fn get_string_match_condition(
    column: impl ColumnTrait,
    value: StringMatch,
) -> Condition {
    let StringMatch { r#match, value } = value;
    match r#match {
        StringMatchType::Equals => column.eq(value),
        StringMatchType::StartsWith => column.starts_with(value),
        StringMatchType::EndsWith => column.ends_with(value),
        StringMatchType::Contains => column.contains(value),
    }
    .into_condition()
}

/// helper function to construct a `sea_query::Condition` from a `DateTimeComparison`
pub(crate) fn get_comparison_condition<T: Into<Value>>(
    column: impl ColumnTrait,
    value: ValueComparison<T>,
) -> Condition {
    let ValueComparison { comparison, value } = value;
    match comparison {
        ComparisonType::Equal => column.eq(value),
        ComparisonType::NotEqual => column.ne(value),
        ComparisonType::LessThan => column.lt(value),
        ComparisonType::GreaterThan => column.gt(value),
        ComparisonType::LessThanOrEqual => column.lte(value),
        ComparisonType::GreaterThanOrEqual => column.gte(value),
    }
    .into_condition()
}

/// helper function to construct an `eq` `sea_query::Condition` with a specific value
pub(crate) fn get_equals_condition(column: impl ColumnTrait, value: impl Into<Value>) -> Condition {
    column.eq(value).into_condition()
}
