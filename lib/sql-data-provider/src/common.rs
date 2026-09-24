use one_core::model::common::GetListResponse;
use one_core::model::list_query::ListQuery;
use one_core::repository::error::DataLayerError;
use sea_orm::{DbErr, EntityTrait, PaginatorTrait, Select};
use serde::de::{Deserialize, Deserializer, Error, Unexpected};
use serde_json::Value;

use crate::mapper::to_data_layer_error;
use crate::transaction_context::TransactionManagerImpl;

/// Do not poll the count future when the caller only needs values.
pub(crate) async fn count_if_requested<'db, Query: PaginatorTrait<'db, TransactionManagerImpl>>(
    include_count: bool,
    query: Query,
    db: &'db TransactionManagerImpl,
) -> Result<Option<u64>, DbErr> {
    if include_count {
        let paginator = query.paginate(db, 1);
        paginator.num_items().await.map(Some)
    } else {
        Ok(None)
    }
}

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

pub(super) fn opt_hex<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<Value>::deserialize(deserializer)?;
    match value.iter().flat_map(Value::as_str).next() {
        None => Ok(None),
        Some(hex) => hex::decode(hex).map_err(Error::custom).map(Some),
    }
}

pub(crate) async fn list_query_with_base_model<
    'db,
    E: EntityTrait,
    ItemErr: Into<DataLayerError>,
    ListItem: TryFrom<E::Model, Error = ItemErr>,
    SortableColumn,
    FV,
    Include,
>(
    query: Select<E>,
    query_params: ListQuery<SortableColumn, FV, Include>,
    db: &'db TransactionManagerImpl,
) -> Result<GetListResponse<ListItem, Option<u64>>, DataLayerError>
where
    Select<E>: PaginatorTrait<'db, TransactionManagerImpl>,
{
    list_query_with_custom_model(query, query_params, db, |model| {
        model.try_into().map_err(ItemErr::into)
    })
    .await
}

pub(crate) async fn list_query_with_custom_model<
    'db,
    E: EntityTrait,
    ListItem,
    SortableColumn,
    FV,
    Include,
    ModelConversion: Fn(E::Model) -> Result<ListItem, DataLayerError>,
>(
    query: Select<E>,
    query_params: ListQuery<SortableColumn, FV, Include>,
    db: &'db TransactionManagerImpl,
    model_conversion: ModelConversion,
) -> Result<GetListResponse<ListItem, Option<u64>>, DataLayerError>
where
    Select<E>: PaginatorTrait<'db, TransactionManagerImpl>,
{
    let (total_items, total_pages, models) = if let Some(pagination) = query_params.pagination {
        let (count, items) = tokio::join!(
            count_if_requested(query_params.include_count, query.to_owned(), db),
            query.all(db)
        );

        let total_items = count.map_err(to_data_layer_error)?;
        let models = items.map_err(to_data_layer_error)?;

        (
            total_items,
            total_items.map(|count| calculate_pages_count(count, pagination.page_size as _)),
            models,
        )
    } else {
        // if no pagination applied, there's no need to SQL query count, all models will be returned by the list query
        let models = query.all(db).await.map_err(to_data_layer_error)?;
        (
            query_params.include_count.then_some(models.len() as u64),
            query_params.include_count.then_some(0),
            models,
        )
    };

    Ok(GetListResponse {
        values: models
            .into_iter()
            .map(model_conversion)
            .collect::<Result<Vec<ListItem>, _>>()?,
        total_pages,
        total_items,
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
