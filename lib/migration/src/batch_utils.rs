use std::collections::HashSet;

use sea_orm::prelude::Expr;
use sea_orm::sea_query::{IntoColumnRef, IntoTableRef, Query, SelectStatement};
use sea_orm::{DbErr, FromQueryResult};
use sea_orm_migration::SchemaManager;

#[derive(FromQueryResult)]
pub(crate) struct IdResult {
    pub id: String,
}

pub(crate) async fn get_ids_batched(
    table: impl IntoTableRef,
    id_column: impl IntoColumnRef,
    linked_entity_id_column: impl IntoColumnRef,
    linked_entities: &[String],
    manager: &SchemaManager<'_>,
) -> Result<Vec<String>, DbErr> {
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
            get_ids(
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

pub(crate) async fn get_ids(
    manager: &SchemaManager<'_>,
    query: &SelectStatement,
) -> Result<Vec<String>, DbErr> {
    let backend = manager.get_database_backend();
    let db = manager.get_connection();

    Ok(IdResult::find_by_statement(backend.build(query))
        .all(db)
        .await?
        .into_iter()
        .map(|res| res.id)
        .collect())
}

pub(crate) async fn delete(
    table: impl IntoTableRef,
    column: impl IntoColumnRef,
    entity_ids: &[String],
    manager: &SchemaManager<'_>,
) -> Result<(), DbErr> {
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
                    .and_where(Expr::col(column.to_owned()).is_in(chunk))
                    .to_owned(),
            )
            .await?;
    }

    Ok(())
}

fn unique_ids(input: &[String]) -> Vec<String> {
    let ids: HashSet<&String> = HashSet::from_iter(input);
    ids.into_iter().map(ToString::to_string).collect()
}
