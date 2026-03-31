use sea_orm::{ConnectionTrait, DbBackend, DbErr};
use sea_orm_migration::SchemaManager;

pub(crate) struct Params {
    pub table: String,
    pub columns: Vec<String>,
    pub soft_delete_column: String,
    pub index_name: String,
}

pub(crate) async fn add_soft_delete_unique_idx(
    params: Params,
    manager: &SchemaManager<'_>,
) -> Result<(), DbErr> {
    let Params {
        table,
        columns,
        soft_delete_column,
        index_name,
    } = params;

    let db = manager.get_connection();
    let quoted_columns = columns
        .iter()
        .map(|c| format!("`{}`", c))
        .collect::<Vec<_>>()
        .join(", ");
    match manager.get_database_backend() {
        DbBackend::Sqlite => {
            let create_unique_index_did = format!(
                "CREATE UNIQUE INDEX `{index_name}` ON `{table}`({quoted_columns}, COALESCE(`{soft_delete_column}`, 'not_deleted'));"
            );
            db.execute_unprepared(&create_unique_index_did).await?;
        }
        _ => {
            let add_generated_column_org_id = format!(
                "ALTER TABLE `{table}` ADD COLUMN IF NOT EXISTS `{soft_delete_column}_materialized` VARCHAR(50) AS (COALESCE(TRIM(`{soft_delete_column}`), 'not_deleted')) PERSISTENT;"
            );
            db.execute_unprepared(&add_generated_column_org_id).await?;
            let create_unique_index_did = format!(
                "CREATE UNIQUE INDEX `{index_name}` ON `{table}`({quoted_columns}, `{soft_delete_column}_materialized`);"
            );
            db.execute_unprepared(&create_unique_index_did).await?;
        }
    }
    Ok(())
}
