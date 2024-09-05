use std::fmt;

use dto_mapper::{convert_inner, try_convert_inner};
use one_core::model::common::GetListResponse;
use serde::Serialize;
use thiserror::Error;
use utoipa::ToSchema;

use crate::dto::common::{GetListQueryParams, GetListResponseRestDTO};

#[derive(Debug, Error)]
pub enum MapperError {
    #[error("ct_codecs error: `{0}`")]
    CtCodecsError(#[from] ct_codecs::Error),
}

impl<T, K> From<GetListResponse<K>> for GetListResponseRestDTO<T>
where
    T: From<K> + Clone + fmt::Debug + Serialize,
{
    fn from(value: GetListResponse<K>) -> Self {
        Self {
            values: convert_inner(value.values),
            total_pages: value.total_pages,
            total_items: value.total_items,
        }
    }
}

pub fn list_try_from<T, K>(
    value: GetListResponse<K>,
) -> Result<GetListResponseRestDTO<T>, MapperError>
where
    T: TryFrom<K> + Clone + fmt::Debug + Serialize,
    MapperError: From<T::Error>,
{
    Ok(GetListResponseRestDTO {
        values: try_convert_inner(value.values)?,
        total_pages: value.total_pages,
        total_items: value.total_items,
    })
}

impl<T, K> From<GetListQueryParams<T>> for one_core::model::common::GetListQueryParams<K>
where
    K: From<T>,
    T: for<'a> ToSchema<'a>,
{
    fn from(value: GetListQueryParams<T>) -> Self {
        Self {
            page: value.page,
            page_size: value.page_size,
            sort: convert_inner(value.sort),
            sort_direction: convert_inner(value.sort_direction),
            name: value.name,
            exact: Some(convert_inner(value.exact.unwrap_or_default())),
            organisation_id: value.organisation_id,
            ids: value.ids,
        }
    }
}
