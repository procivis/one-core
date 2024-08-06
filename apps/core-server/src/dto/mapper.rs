use dto_mapper::convert_inner;
use one_core::model::list_filter::{ListFilterCondition, ListFilterValue};
use one_core::model::list_query::{ListPagination, ListQuery, ListSorting};
use one_core::service::error::{ErrorCodeMixin, ServiceError};
use serde::Deserialize;
use utoipa::openapi::path::ParameterIn;
use utoipa::openapi::{RefOr, Schema};
use utoipa::{IntoParams, ToSchema};

use super::common::SortDirection;
use super::error::{Cause, ErrorCode, ErrorResponseRestDTO};
use crate::dto::common::ListQueryParamsRest;

impl<
        FilterRest,
        SortableColumnRest,
        SortableColumn,
        Filter: ListFilterValue,
        IncludeRest,
        Include,
    > From<ListQueryParamsRest<FilterRest, SortableColumnRest, IncludeRest>>
    for ListQuery<SortableColumn, Filter, Include>
where
    FilterRest: IntoParams + Into<ListFilterCondition<Filter>>,
    SortableColumnRest: for<'a> ToSchema<'a> + Into<SortableColumn>,
    IncludeRest: for<'a> ToSchema<'a> + Into<Include>,
{
    fn from(value: ListQueryParamsRest<FilterRest, SortableColumnRest, IncludeRest>) -> Self {
        Self {
            pagination: Some(ListPagination {
                page: value.page,
                page_size: value.page_size,
            }),
            sorting: value.sort.map(|column| ListSorting {
                column: column.into(),
                direction: convert_inner(value.sort_direction),
            }),
            filtering: Some(value.filter.into()),
            include: value.include.map(convert_inner),
        }
    }
}

// Custom definition of IntoParams for the ListQueryParamsRest in order to flatten the filter params in swagger-ui
impl<Filter, SortColumn, Include> IntoParams for ListQueryParamsRest<Filter, SortColumn, Include>
where
    Filter: IntoParams,
    SortColumn: for<'a> ToSchema<'a>,
    Include: for<'a> ToSchema<'a>,
{
    fn into_params(
        _parameter_in_provider: impl Fn() -> Option<ParameterIn>,
    ) -> Vec<utoipa::openapi::path::Parameter> {
        let mut params =
            PartialQueryParamsRest::<SortColumn, Include>::into_params(|| Some(ParameterIn::Query));

        // remove empty include[] params
        params.retain(|param| {
            if let Some(RefOr::T(Schema::Array(array))) = &param.schema {
                if let RefOr::T(Schema::Object(obj)) = array.items.as_ref() {
                    return obj.enum_values.is_some();
                }
            }
            true
        });

        params.append(&mut Filter::into_params(|| Some(ParameterIn::Query)));
        params
    }
}

// only used for generation of swagger-ui params for pagination and sorting
#[derive(Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct PartialQueryParamsRest<SortColumn: for<'a> ToSchema<'a>, Include: for<'a> ToSchema<'a>> {
    pub page: u32,
    pub page_size: u32,

    #[param(inline)]
    pub sort: Option<SortColumn>,
    pub sort_direction: Option<SortDirection>,

    #[param(inline, rename = "include[]")]
    pub include: Option<Vec<Include>>,
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
