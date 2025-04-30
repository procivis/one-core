use std::fmt::Write;

use one_core::model::common::SortDirection;
use one_core::model::list_filter::{
    ComparisonType, ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
    ValueComparison,
};
use one_core::model::list_query::ListQuery;
use sea_orm::prelude::Expr;
use sea_orm::query::*;
use sea_orm::sea_query::{Func, IntoCondition, SimpleExpr};
use sea_orm::{ColumnTrait, EntityTrait, RelationDef};

use crate::mapper::order_from_sort_direction;

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

pub trait IntoJoinRelations: ListFilterValue {
    fn get_join(&self) -> Vec<JoinRelation>;
}

pub trait SelectWithFilterJoin<SortableColumn, JoinValue, Include>
where
    SortableColumn: IntoSortingColumn,
    JoinValue: IntoJoinRelations,
{
    /// applies all `query.filtering` required relations
    fn with_filter_join(self, query: &ListQuery<SortableColumn, JoinValue, Include>) -> Self;
}

impl<T, SortableColumn, JoinValue, Include> SelectWithFilterJoin<SortableColumn, JoinValue, Include>
    for Select<T>
where
    T: EntityTrait,
    SortableColumn: IntoSortingColumn,
    JoinValue: IntoJoinRelations,
{
    fn with_filter_join(self, query: &ListQuery<SortableColumn, JoinValue, Include>) -> Select<T> {
        let mut result = self;

        if let Some(filter) = &query.filtering {
            let mut unique_relations: Vec<JoinRelation> = vec![];
            for relation in get_join_relations(filter) {
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
fn get_join_relations<JoinValue: IntoJoinRelations>(
    filter: &ListFilterCondition<JoinValue>,
) -> Vec<JoinRelation> {
    let mut result = vec![];
    match filter {
        ListFilterCondition::Value(v) => {
            result.append(&mut v.get_join());
        }
        ListFilterCondition::And(filter_list) => {
            for value in filter_list {
                result.append(&mut get_join_relations(value));
            }
        }
        ListFilterCondition::Or(filter_list) => {
            for value in filter_list {
                result.append(&mut get_join_relations(value));
            }
        }
    }

    result
}

pub trait SelectWithListQuery<SortableColumn, FilterValue, Include>
where
    SortableColumn: IntoSortingColumn,
    FilterValue: IntoFilterCondition,
{
    /// applies all `query` declared constrains (filtering, sorting and pagination) on the query
    fn with_list_query(self, query: &ListQuery<SortableColumn, FilterValue, Include>) -> Self;
}

impl<T, SortableColumn, FilterValue, Include>
    SelectWithListQuery<SortableColumn, FilterValue, Include> for Select<T>
where
    T: EntityTrait,
    SortableColumn: IntoSortingColumn,
    FilterValue: IntoFilterCondition,
{
    fn with_list_query(self, query: &ListQuery<SortableColumn, FilterValue, Include>) -> Select<T> {
        let mut result = self;

        if let Some(filter) = &query.filtering {
            if !filter.is_empty() {
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
                if !condition.is_empty() {
                    result = result.add(get_filter_condition(condition));
                }
            }
            result
        }
        ListFilterCondition::Or(conditions) => {
            let mut result = Condition::any();
            for condition in conditions {
                if !condition.is_empty() {
                    result = result.add(get_filter_condition(condition));
                }
            }
            result
        }
        ListFilterCondition::Value(value) => value.to_owned().get_condition(),
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

pub struct SubStr;

impl sea_orm::Iden for SubStr {
    fn unquoted(&self, s: &mut dyn Write) {
        write!(s, "substr").unwrap();
    }
}

pub struct Hex;

impl sea_orm::Iden for Hex {
    fn unquoted(&self, s: &mut dyn Write) {
        write!(s, "hex").unwrap();
    }
}

pub(crate) fn get_blob_match_condition(
    column: impl ColumnTrait,
    value: StringMatch,
    limit: u64,
) -> Condition {
    let StringMatch { r#match, value } = value;
    let slice = Expr::expr(
        Func::cust(Hex).arg(Func::cust(SubStr).arg(column.into_expr()).arg(1).arg(limit)),
    );
    let value = hex::encode(value);

    match r#match {
        StringMatchType::Equals => slice.eq(value),
        StringMatchType::StartsWith => {
            let pattern = format!("{value}%");
            slice.like(pattern)
        }
        StringMatchType::EndsWith => {
            let pattern = format!("%{value}");
            slice.like(pattern)
        }
        StringMatchType::Contains => {
            let pattern = format!("%{value}%");
            slice.like(pattern)
        }
    }
    .into_condition()
}
