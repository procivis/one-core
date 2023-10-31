use crate::mapper::order_from_sort_direction;
use one_core::model::common::{ExactColumn, GetListQueryParams, SortDirection};
use sea_orm::{entity::*, query::*, sea_query::SimpleExpr, EntityTrait, QueryOrder, QuerySelect};
use std::str::FromStr;

// column conversion
pub trait GetEntityColumn {
    fn get_simple_expr(&self) -> SimpleExpr;
}

pub trait SelectWithListQuery<SortableColumn, FilterColumn>
where
    SortableColumn: GetEntityColumn,
    FilterColumn: ColumnTrait,
{
    /// Add expressions coming via GET url params
    fn with_list_query(
        self,
        query_params: &GetListQueryParams<SortableColumn>,
        filter_name_columns: &Option<Vec<FilterColumn>>,
    ) -> Self;

    /// Add expressions coming via GET url params
    fn with_organisation_id(
        self,
        query_params: &GetListQueryParams<SortableColumn>,
        column: &FilterColumn,
    ) -> Self;
}

impl<T, SortableColumn, FilterColumn> SelectWithListQuery<SortableColumn, FilterColumn>
    for Select<T>
where
    T: EntityTrait,
    SortableColumn: GetEntityColumn,
    FilterColumn: ColumnTrait,
{
    fn with_list_query(
        self,
        query_params: &GetListQueryParams<SortableColumn>,
        filter_name_columns: &Option<Vec<FilterColumn>>,
    ) -> Select<T> {
        let mut result = self;

        // filtering by name
        if let (Some(filter_name), Some(filter_columns)) =
            (&query_params.name, &filter_name_columns)
        {
            if !filter_columns.is_empty() {
                let mut conditions = Condition::any();

                for column in filter_columns {
                    if let Some(exact_columns) = query_params.exact.as_ref() {
                        // If exact columns are defined and not empty
                        // don't filter over any other columns
                        if !exact_columns.is_empty() {
                            for column in filter_columns {
                                if let Ok(exact_col) = ExactColumn::from_str(&column.to_string()) {
                                    if query_params
                                        .exact
                                        .as_ref()
                                        .map(|i| i.contains(&exact_col))
                                        .unwrap_or_else(|| false)
                                    {
                                        conditions = conditions.add(column.eq(filter_name));
                                    }
                                }
                            }
                            continue;
                        }
                    }
                    conditions = conditions.add(column.starts_with(filter_name));
                }
                result = result.filter(conditions);
            }
        }

        // sorting
        if let Some(sort_column) = &query_params.sort {
            result = result.order_by(
                sort_column.get_simple_expr(),
                order_from_sort_direction(
                    query_params
                        .sort_direction
                        .unwrap_or(SortDirection::Ascending),
                ),
            );
        }

        // pagination
        let limit: u64 = query_params.page_size as u64;
        let offset: u64 = (query_params.page * query_params.page_size) as u64;
        result.offset(offset).limit(limit)
    }

    fn with_organisation_id(
        self,
        query_params: &GetListQueryParams<SortableColumn>,
        column: &FilterColumn,
    ) -> Select<T> {
        let conditions = Condition::all().add(column.eq(&query_params.organisation_id));
        self.filter(conditions)
    }
}

#[cfg(test)]
pub fn from_pagination<T: GetEntityColumn>(
    page: u32,
    page_size: u32,
    organisation_id: String,
) -> GetListQueryParams<T> {
    GetListQueryParams {
        page,
        page_size,
        sort: None,
        exact: None,
        sort_direction: None,
        name: None,
        organisation_id,
    }
}
