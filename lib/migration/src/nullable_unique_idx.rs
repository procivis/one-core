use sea_orm::sea_query::{Index, IntoIden};
use sea_orm::{ConnectionTrait, DatabaseBackend, DbErr};
use sea_orm_migration::SchemaManager;

#[derive(Debug)]
pub(crate) struct NullableIdxOpts<C: IntoIden> {
    pub non_nullable_columns: Vec<C>,
    pub null_value: Option<&'static str>,
    pub nullable_column_index_pos: Option<usize>,
    pub materialized_column_size_limit: Option<usize>,
}

impl<C: IntoIden> Default for NullableIdxOpts<C> {
    fn default() -> Self {
        Self {
            non_nullable_columns: vec![],
            null_value: None,
            nullable_column_index_pos: None,
            materialized_column_size_limit: None,
        }
    }
}

pub(crate) async fn add_nullable_unique_idx<T: IntoIden + 'static, C: IntoIden + 'static>(
    table: T,
    nullable_column: C,
    index_name: &str,
    options: NullableIdxOpts<C>,
    manager: &SchemaManager<'_>,
) -> Result<(), DbErr> {
    let NullableIdxOpts {
        non_nullable_columns,
        null_value,
        nullable_column_index_pos,
        materialized_column_size_limit,
    } = options;
    let db_backend = manager.get_database_backend();
    if DatabaseBackend::Postgres == db_backend {
        pg_sql_nullable_unique_idx(
            manager,
            table,
            non_nullable_columns,
            nullable_column,
            index_name,
            nullable_column_index_pos,
        )
        .await?;
        return Ok(());
    }

    let table = table.into_iden().to_string();
    let nullable_column = nullable_column.into_iden().to_string();
    let null_value = null_value.unwrap_or("not_deleted");
    let materialized_column_size_limit = materialized_column_size_limit.unwrap_or(50);

    let quoted_materialzed_column_or_expr = if DatabaseBackend::Sqlite == db_backend {
        format!("COALESCE(`{nullable_column}`, '{null_value}')")
    } else {
        format!("`{nullable_column}_materialized`")
    };
    let mut quoted_column_names = non_nullable_columns
        .into_iter()
        .map(|c| format!("`{}`", c.into_iden()))
        .collect::<Vec<_>>();
    if let Some(pos) = nullable_column_index_pos {
        quoted_column_names.insert(pos, quoted_materialzed_column_or_expr.clone());
    } else {
        quoted_column_names.push(quoted_materialzed_column_or_expr.clone());
    }
    let quoted_columns = quoted_column_names.join(", ");

    let db = manager.get_connection();
    if db_backend == DatabaseBackend::MySql {
        let add_materialized_column_stmt = format!(
            "ALTER TABLE `{table}` ADD COLUMN IF NOT EXISTS {quoted_materialzed_column_or_expr} VARCHAR({materialized_column_size_limit}) AS (COALESCE(TRIM(`{nullable_column}`), '{null_value}')) PERSISTENT;"
        );
        db.execute_unprepared(&add_materialized_column_stmt).await?;
    }
    let create_unique_index_did =
        format!("CREATE UNIQUE INDEX IF NOT EXISTS `{index_name}` ON `{table}`({quoted_columns});");
    db.execute_unprepared(&create_unique_index_did).await?;
    Ok(())
}

async fn pg_sql_nullable_unique_idx<T: IntoIden + 'static, C: IntoIden + 'static>(
    manager: &SchemaManager<'_>,
    table: T,
    columns: Vec<C>,
    nullable_column: C,
    index_name: &str,
    nullable_column_index_pos: Option<usize>,
) -> Result<(), DbErr> {
    let mut index = Index::create()
        .if_not_exists()
        .name(index_name)
        .table(table)
        .unique()
        .nulls_not_distinct()
        .to_owned();
    let mut col_idens = columns
        .into_iter()
        .map(|c| c.into_iden())
        .collect::<Vec<_>>();
    if let Some(pos) = nullable_column_index_pos {
        col_idens.insert(pos, nullable_column.into_iden());
    } else {
        col_idens.push(nullable_column.into_iden());
    }
    for col in col_idens {
        index.col(col);
    }
    manager.create_index(index).await?;
    Ok(())
}
