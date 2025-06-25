use std::fmt;

use one_core::model::common::GetListResponse;
use one_core::service::error::ServiceError;
use one_dto_mapper::{convert_inner, try_convert_inner};
use serde::Serialize;
use thiserror::Error;

use crate::dto::common::GetListResponseRestDTO;

#[derive(Debug, Error)]
pub enum MapperError {
    #[error("ct_codecs error: `{0}`")]
    CtCodecsError(#[from] ct_codecs::Error),
}

impl<T, K> From<GetListResponse<K>> for GetListResponseRestDTO<T>
where
    T: From<K> + fmt::Debug + Serialize,
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
    T: TryFrom<K> + fmt::Debug + Serialize,
    MapperError: From<T::Error>,
{
    Ok(GetListResponseRestDTO {
        values: try_convert_inner(value.values)?,
        total_pages: value.total_pages,
        total_items: value.total_items,
    })
}

impl From<MapperError> for ServiceError {
    fn from(value: MapperError) -> Self {
        ServiceError::MappingError(value.to_string())
    }
}
