use sea_orm::strum::IntoEnumIterator;
use sea_orm::{ConnectionTrait, DbErr, Iden, Statement};
use sea_orm_migration::SchemaManager;

pub async fn add_enum_variant<T: Iden + IntoEnumIterator>(
    manager: &SchemaManager<'_>,
    table: &str,
    column: &str,
) -> Result<(), DbErr> {
    match manager.get_database_backend() {
        backend @ sea_orm::DatabaseBackend::MySql => {
            let enum_values: Vec<String> = T::iter().map(|action| action.to_string()).collect();

            let values = format!("'{}'", enum_values.join("', '"));

            let query = format!(
                r#"ALTER TABLE {table} CHANGE COLUMN {column} {column} ENUM({values}) NOT NULL;"#
            );

            let change_stmt = Statement::from_string(backend, &query);

            manager.get_connection().execute(change_stmt).await?;
        }
        sea_orm::DatabaseBackend::Postgres | sea_orm::DatabaseBackend::Sqlite => {}
    }
    Ok(())
}
