use sea_orm::{entity::*, query::*, EntityTrait, IntoSimpleExpr, Order, QueryOrder, QuerySelect};
use serde::Deserialize;
use std::convert::From;
use utoipa::{IntoParams, ToSchema};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, ToSchema)]
pub enum SortDirection {
    #[serde(rename = "ASC")]
    Ascending,
    #[serde(rename = "DESC")]
    Descending,
}

impl From<SortDirection> for Order {
    fn from(direction: SortDirection) -> Self {
        match direction {
            SortDirection::Ascending => Order::Asc,
            SortDirection::Descending => Order::Desc,
        }
    }
}

// column conversion
pub trait GetEntityColumn {
    type Column;

    fn get_column(&self) -> Self::Column
    where
        Self::Column: IntoSimpleExpr;
}

#[derive(Clone, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(rename_all = "camelCase")]
pub struct GetListQueryParams<SortableColumn>
where
    SortableColumn: GetEntityColumn,
{
    // pagination
    pub page: u32,
    pub page_size: u32,

    // sorting
    #[param(value_type = Option<String>)]
    pub sort: Option<SortableColumn>,
    pub sort_direction: Option<SortDirection>,

    // filtering
    pub name: Option<String>,
    pub organisation_id: String,
}

pub trait SelectWithListQuery<SortableColumn, FilterColumn>
where
    SortableColumn: GetEntityColumn,
    SortableColumn::Column: IntoSimpleExpr,
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
    SortableColumn::Column: IntoSimpleExpr,
    FilterColumn: ColumnTrait,
{
    fn with_list_query(
        self,
        query_params: &GetListQueryParams<SortableColumn>,
        filter_name_columns: &Option<Vec<FilterColumn>>,
    ) -> Select<T> {
        let mut result = self;

        // filtering by name
        if let Some(filter_name) = &query_params.name {
            if let Some(filter_columns) = &filter_name_columns {
                if !filter_columns.is_empty() {
                    let mut conditions = Condition::any();
                    for column in filter_columns {
                        conditions = conditions.add(column.starts_with(filter_name));
                    }
                    result = result.filter(conditions);
                }
            }
        }

        // sorting
        if let Some(sort_column) = &query_params.sort {
            result = result.order_by(
                sort_column.get_column(),
                Order::from(
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
impl<T> GetListQueryParams<T>
where
    T: GetEntityColumn,
{
    pub fn from_pagination(page: u32, page_size: u32, organisation_id: String) -> Self {
        Self {
            page,
            page_size,
            sort: None,
            sort_direction: None,
            name: None,
            organisation_id,
        }
    }
}
