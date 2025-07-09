use one_core::model::common::GetListResponse;
use one_core::model::list_query::ListQuery;
use one_core::repository::error::DataLayerError;
use one_dto_mapper::convert_inner;
use sea_orm::{DatabaseConnection, EntityTrait, PaginatorTrait, Select};
use serde::de::{Deserialize, Deserializer, Error, Unexpected};

use crate::mapper::to_data_layer_error;

pub(super) fn calculate_pages_count(total_items_count: u64, page_size: u64) -> u64 {
    if page_size == 0 {
        return 0;
    }

    (total_items_count / page_size) + std::cmp::min(total_items_count % page_size, 1)
}

pub(super) fn bool_from_int<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    match u8::deserialize(deserializer)? {
        0 => Ok(false),
        1 => Ok(true),
        other => Err(Error::invalid_value(
            Unexpected::Unsigned(other as u64),
            &"zero or one",
        )),
    }
}

pub(crate) async fn list_query_with_base_model<
    'db,
    E: EntityTrait,
    ListItem: From<E::Model>,
    SortableColumn,
    FV,
    Include,
>(
    query: Select<E>,
    query_params: ListQuery<SortableColumn, FV, Include>,
    db: &'db DatabaseConnection,
) -> Result<GetListResponse<ListItem>, DataLayerError>
where
    Select<E>: PaginatorTrait<'db, DatabaseConnection>,
{
    let limit = query_params
        .pagination
        .as_ref()
        .map(|pagination| pagination.page_size as _);

    let (items_count, items) =
        tokio::join!(PaginatorTrait::count(query.to_owned(), db), query.all(db));

    let items_count = items_count.map_err(to_data_layer_error)?;
    let items = items.map_err(to_data_layer_error)?;

    Ok(GetListResponse::<ListItem> {
        values: convert_inner(items),
        total_pages: calculate_pages_count(items_count, limit.unwrap_or(0)),
        total_items: items_count,
    })
}

#[cfg(test)]
mod tests {
    use similar_asserts::assert_eq;

    use super::calculate_pages_count;

    #[test]
    fn test_calculate_pages_count() {
        assert_eq!(0, calculate_pages_count(1, 0));

        assert_eq!(1, calculate_pages_count(1, 1));
        assert_eq!(1, calculate_pages_count(1, 2));
        assert_eq!(1, calculate_pages_count(1, 100));

        assert_eq!(5, calculate_pages_count(50, 10));
        assert_eq!(6, calculate_pages_count(51, 10));
        assert_eq!(6, calculate_pages_count(52, 10));
        assert_eq!(6, calculate_pages_count(60, 10));
        assert_eq!(7, calculate_pages_count(61, 10));
    }
}
