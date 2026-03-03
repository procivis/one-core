use std::collections::HashSet;
use std::hash::Hash;

use sea_orm::prelude::Expr;
use sea_orm::sea_query::{IntoColumnRef, IntoTableRef, Query, SelectStatement, SimpleExpr};
use sea_orm::{DbErr, FromQueryResult, TryGetable};
use sea_orm_migration::SchemaManager;

#[derive(FromQueryResult)]
pub(crate) struct IdResult<T: TryGetable> {
    pub id: T,
}

pub(crate) async fn get_ids_batched<T: TryGetable>(
    table: impl IntoTableRef,
    id_column: impl IntoColumnRef,
    linked_entity_id_column: impl IntoColumnRef,
    linked_entities: &[String],
    manager: &SchemaManager<'_>,
) -> Result<Vec<T>, DbErr> {
    if linked_entities.is_empty() {
        return Ok(vec![]);
    }

    let table = table.into_table_ref();
    let id_column = id_column.into_column_ref();
    let linked_entity_id_column = linked_entity_id_column.into_column_ref();

    let ids = unique_ids(linked_entities);
    let mut result = vec![];
    for (index, chunk) in ids.chunks(1000).enumerate() {
        tracing::debug!(
            "Fetching {table:?}.{id_column:?}, chunk {index}/{}",
            ids.len() / 1000
        );

        result.extend(
            get_ids::<T>(
                manager,
                Query::select()
                    .expr_as(Expr::col(id_column.to_owned()), "id")
                    .from(table.to_owned())
                    .and_where(Expr::col(linked_entity_id_column.to_owned()).is_in(chunk))
                    .and_where(Expr::col(id_column.to_owned()).is_not_null()),
            )
            .await?,
        );
    }
    Ok(result)
}

pub(crate) async fn get_ids<T: TryGetable>(
    manager: &SchemaManager<'_>,
    query: &SelectStatement,
) -> Result<Vec<T>, DbErr> {
    let backend = manager.get_database_backend();
    let db = manager.get_connection();

    Ok(IdResult::<T>::find_by_statement(backend.build(query))
        .all(db)
        .await?
        .into_iter()
        .map(|res| res.id)
        .collect())
}

pub(crate) async fn delete<T>(
    table: impl IntoTableRef,
    column: impl IntoColumnRef,
    entity_ids: &[T],
    manager: &SchemaManager<'_>,
) -> Result<(), DbErr>
where
    T: Eq + Hash + Clone + Into<SimpleExpr>,
{
    if entity_ids.is_empty() {
        return Ok(());
    }

    let table = table.into_table_ref();
    let column = column.into_column_ref();

    let ids = unique_ids(entity_ids);
    for (index, chunk) in ids.chunks(1000).enumerate() {
        tracing::debug!("Deleting {table:?}, chunk {index}/{}", ids.len() / 1000);

        manager
            .exec_stmt(
                Query::delete()
                    .from_table(table.to_owned())
                    .and_where(Expr::col(column.to_owned()).is_in(chunk.to_vec()))
                    .to_owned(),
            )
            .await?;
    }

    Ok(())
}

fn unique_ids<T: Eq + Hash + Clone>(input: &[T]) -> Vec<T> {
    let ids: HashSet<&T> = HashSet::from_iter(input);
    ids.into_iter().map(ToOwned::to_owned).collect()
}
