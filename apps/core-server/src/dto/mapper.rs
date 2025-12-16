use one_core::error::ErrorCodeMixin;
use one_core::model::list_filter::ListFilterCondition;
use one_core::model::list_query::{ListPagination, ListQuery, ListSorting};
use one_core::proto::session_provider::SessionProvider;
use one_core::service::error::{BusinessLogicError, ServiceError};
use one_dto_mapper::convert_inner;
use shared_types::OrganisationId;
use strum::EnumMessage;
use utoipa::openapi::path::ParameterIn;
use utoipa::openapi::schema::ArrayItems;
use utoipa::openapi::{RefOr, Schema};
use utoipa::{IntoParams, ToSchema};

use super::common::SortDirection;
use super::error::{Cause, ErrorResponseRestDTO};
use crate::dto::common::ListQueryParamsRest;
use crate::session::CoreServerSessionProvider;

impl<FilterRest, SortableColumnRest, SortableColumn, Filter, IncludeRest, Include>
    TryFrom<ListQueryParamsRest<FilterRest, SortableColumnRest, IncludeRest>>
    for ListQuery<SortableColumn, Filter, Include>
where
    FilterRest: TryInto<ListFilterCondition<Filter>>,
    SortableColumnRest: Into<SortableColumn>,
    IncludeRest: Into<Include>,
{
    type Error = FilterRest::Error;

    fn try_from(
        value: ListQueryParamsRest<FilterRest, SortableColumnRest, IncludeRest>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            pagination: Some(ListPagination {
                page: value.page,
                page_size: value.page_size.inner(),
            }),
            sorting: value.sort.map(|column| ListSorting {
                column: column.into(),
                direction: convert_inner(value.sort_direction),
            }),
            filtering: Some(value.filter.try_into()?),
            include: value.include.map(convert_inner),
        })
    }
}

// Custom definition of IntoParams for the ListQueryParamsRest in order to flatten the filter params in swagger-ui
impl<Filter, SortColumn, Include> IntoParams for ListQueryParamsRest<Filter, SortColumn, Include>
where
    Filter: IntoParams,
    SortColumn: ToSchema,
    Include: ToSchema,
{
    fn into_params(
        _parameter_in_provider: impl Fn() -> Option<ParameterIn>,
    ) -> Vec<utoipa::openapi::path::Parameter> {
        let mut params =
            PartialQueryParamsRest::<SortColumn, Include>::into_params(|| Some(ParameterIn::Query));

        // remove empty include[] params
        params.retain(|param| {
            if let Some(RefOr::T(Schema::Array(array))) = &param.schema
                && let ArrayItems::RefOrSchema(ref_or) = &array.items
                && let RefOr::T(Schema::Object(obj)) = ref_or.as_ref()
            {
                return obj.enum_values.is_some();
            }
            true
        });

        params.append(&mut Filter::into_params(|| Some(ParameterIn::Query)));
        params
    }
}

// only used for generation of swagger-ui params for pagination, sorting and data inclusion
#[derive(IntoParams)]
#[into_params(rename_all = "camelCase")]
#[expect(dead_code)]
struct PartialQueryParamsRest<SortColumn: ToSchema, Include: ToSchema> {
    /// The page number to retrieve (0-based indexing).
    #[param(example = 0, minimum = 0)]
    pub page: u32,
    /// Number of items to return per page. If omitted, defaults to 30.
    #[param(default = 30, minimum = 1, maximum = 1000)]
    pub page_size: u32,

    /// The field value to sort results by.
    #[param(inline, nullable = false)]
    pub sort: Option<SortColumn>,
    /// Direction to sort results. If a sorting value is passed, the
    /// direction defaults to ASC.
    #[param(nullable = false)]
    pub sort_direction: Option<SortDirection>,

    /// Additional fields to include in response objects.
    #[param(rename = "include[]", inline, nullable = false)]
    pub include: Option<Vec<Include>>,
}

impl<E: ErrorCodeMixin> From<&E> for ErrorResponseRestDTO {
    fn from(error: &E) -> Self {
        let code = error.error_code();
        let cause = Cause::with_message_from_error(error);

        ErrorResponseRestDTO {
            code: code.into(),
            message: code.get_message().unwrap_or_default().to_string(),
            cause: Some(cause),
        }
    }
}

/// Picks either organisation ID passed via JSON body or query parameter of the request (preferred)
/// or organisation ID passed via STS token.
///
/// It fails if no organisation ID is specified.
pub(crate) fn fallback_organisation_id_from_session(
    call_argument: Option<OrganisationId>,
) -> Result<OrganisationId, ServiceError> {
    if let Some(organisation_id) = call_argument {
        return Ok(organisation_id);
    }

    let Some(session) = CoreServerSessionProvider.session() else {
        return Err(BusinessLogicError::OrganisationNotSpecified.into());
    };

    session
        .organisation_id
        .ok_or(BusinessLogicError::OrganisationNotSpecified.into())
}
