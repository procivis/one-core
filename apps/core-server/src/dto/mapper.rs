use dto_mapper::convert_inner;
use one_core::{
    model::{
        list_filter::{ListFilterCondition, ListFilterValue},
        list_query::{ListPagination, ListQuery, ListSorting},
    },
    service::error::ServiceError,
};
use serde::Deserialize;
use utoipa::{openapi::path::ParameterIn, IntoParams, ToSchema};

use crate::dto::common::ListQueryParamsRest;

use super::{
    common::SortDirection,
    error::{Cause, ErrorCode, ErrorResponseRestDTO},
};

impl<FilterRest, SortableColumnRest, SortableColumn, Filter: ListFilterValue>
    TryFrom<ListQueryParamsRest<FilterRest, SortableColumnRest>>
    for ListQuery<SortableColumn, Filter>
where
    FilterRest: IntoParams + TryInto<ListFilterCondition<Filter>>,
    SortableColumnRest: for<'a> ToSchema<'a> + Into<SortableColumn>,
    ServiceError: From<<FilterRest as TryInto<ListFilterCondition<Filter>>>::Error>,
{
    type Error = ServiceError;

    fn try_from(
        value: ListQueryParamsRest<FilterRest, SortableColumnRest>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            pagination: Some(ListPagination {
                page: value.page,
                page_size: value.page_size,
            }),
            sorting: value.sort.map(|column| ListSorting {
                column: column.into(),
                direction: convert_inner(value.sort_direction),
            }),
            filtering: Some(value.filter.try_into()?),
        })
    }
}

// Custom definition of IntoParams for the ListQueryParamsRest in order to flatten the filter params in swagger-ui
impl<Filter, SortColumn> IntoParams for ListQueryParamsRest<Filter, SortColumn>
where
    Filter: IntoParams,
    SortColumn: for<'a> ToSchema<'a>,
{
    fn into_params(
        _parameter_in_provider: impl Fn() -> Option<ParameterIn>,
    ) -> Vec<utoipa::openapi::path::Parameter> {
        let mut params =
            PartialQueryParamsRest::<SortColumn>::into_params(|| Some(ParameterIn::Query));
        params.append(&mut Filter::into_params(|| Some(ParameterIn::Query)));
        params
    }
}

// only used for generation of swagger-ui params for pagination and sorting
#[derive(Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct PartialQueryParamsRest<SortColumn: for<'a> ToSchema<'a>> {
    pub page: u32,
    pub page_size: u32,

    #[param(inline)]
    pub sort: Option<SortColumn>,
    pub sort_direction: Option<SortDirection>,
}

impl From<&ServiceError> for ErrorResponseRestDTO {
    fn from(error: &ServiceError) -> Self {
        let code = error.error_code();
        let cause = Cause::with_message_from_error(error);

        ErrorResponseRestDTO {
            code: ErrorCode::from(code),
            message: code.to_string(),
            cause: Some(cause),
        }
    }
}
