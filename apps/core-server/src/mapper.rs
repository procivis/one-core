use crate::dto::common::{ExactColumn, GetListQueryParams, GetListResponseRestDTO, SortDirection};
use serde::Serialize;
use std::fmt;
use thiserror::Error;
use utoipa::ToSchema;

#[derive(Debug, Error)]
pub enum MapperError {
    #[error("ct_codecs error: `{0}`")]
    CtCodecsError(#[from] ct_codecs::Error),
}

impl<T, K> From<one_core::model::common::GetListResponse<K>> for GetListResponseRestDTO<T>
where
    T: From<K> + Clone + fmt::Debug + Serialize,
{
    fn from(value: one_core::model::common::GetListResponse<K>) -> Self {
        Self {
            values: value.values.into_iter().map(|item| item.into()).collect(),
            total_pages: value.total_pages,
            total_items: value.total_items,
        }
    }
}

pub fn list_try_from<T, K>(
    value: one_core::model::common::GetListResponse<K>,
) -> Result<GetListResponseRestDTO<T>, MapperError>
where
    T: TryFrom<K> + Clone + fmt::Debug + Serialize,
    MapperError: From<<T as TryFrom<K>>::Error>,
{
    Ok(GetListResponseRestDTO {
        values: value
            .values
            .into_iter()
            .map(|item| item.try_into())
            .collect::<Result<Vec<_>, _>>()
            .map_err(MapperError::from)?,
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
            sort: value.sort.map(|sort| sort.into()),
            sort_direction: value.sort_direction.map(|dir| dir.into()),
            name: value.name,
            exact: Some(
                value
                    .exact
                    .unwrap_or_default()
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            ),
            organisation_id: value.organisation_id,
        }
    }
}

impl From<ExactColumn> for one_core::model::common::ExactColumn {
    fn from(value: ExactColumn) -> Self {
        match value {
            ExactColumn::Name => one_core::model::common::ExactColumn::Name,
        }
    }
}

impl From<SortDirection> for one_core::model::common::SortDirection {
    fn from(value: SortDirection) -> Self {
        match value {
            SortDirection::Ascending => one_core::model::common::SortDirection::Ascending,
            SortDirection::Descending => one_core::model::common::SortDirection::Descending,
        }
    }
}
