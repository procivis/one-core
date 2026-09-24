use sea_orm::DbErr;
use sea_orm::sea_query::TableCreateStatement;
use sea_orm_migration::SchemaManager;
use sea_orm_migration::prelude::IndexCreateStatement;

use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

pub(crate) async fn table_with_indexes(
    mut stmt: TableCreateStatement,
    mut indexes: Vec<IndexCreateStatement>,
    manager: &SchemaManager<'_>,
) -> Result<(), DbErr> {
    // SeaOrm does not create the `IF NOT EXISTS` clause for MySQL backend (because it's apparently not supported)
    // MariaDB would support that syntax, but SeaOrm does not know.
    // Hence, for MySQL we fold the index creation into the table create statement.
    match manager.supported_db_type() {
        SupportedDbType::MySql => {
            for index in indexes.iter_mut() {
                stmt.index(index);
            }
            manager.create_table(stmt).await
        }
        SupportedDbType::Sqlite | SupportedDbType::Postgres => {
            manager.create_table(stmt).await?;
            for index in indexes {
                manager.create_index(index).await?;
            }
            Ok(())
        }
    }
}
