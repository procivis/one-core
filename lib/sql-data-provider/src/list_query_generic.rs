use crate::mapper::order_from_sort_direction;
use one_core::model::{
    common::SortDirection,
    list_filter::{ListFilterCondition, ListFilterValue, StringMatch, StringMatchType},
    list_query::ListQuery,
};
use sea_orm::{
    query::*,
    sea_query::{IntoCondition, SimpleExpr},
    ColumnTrait, EntityTrait, QueryOrder, QuerySelect,
};

pub trait IntoSortingColumn {
    /// converts declared sorting column into a sea-orm column
    fn get_column(&self) -> SimpleExpr;
}

pub trait IntoFilterCondition: Clone + ListFilterValue {
    /// converts single query field into a sea-orm condition
    fn get_condition(self) -> Condition;
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

/// helper function to construct an `eq` `sea_query::Condition` with a specific value
pub(crate) fn get_equals_condition(column: impl ColumnTrait, value: impl Into<Value>) -> Condition {
    column.eq(value).into_condition()
}
