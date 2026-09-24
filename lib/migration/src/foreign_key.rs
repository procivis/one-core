use sea_orm::{ConnectionTrait, DbErr};
use sea_orm_migration::SchemaManager;

use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

pub(crate) async fn disable_foreign_key_checks(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    match manager.supported_db_type() {
        SupportedDbType::MySql => {
            manager
                .get_connection()
                .execute_unprepared("SET FOREIGN_KEY_CHECKS=0;")
                .await?;
        }
        SupportedDbType::Postgres => {
            // No-op because Postgres doesn't support disabling foreign key constraints globally.
        }
        SupportedDbType::Sqlite => {
            manager
                .get_connection()
                .execute_unprepared("PRAGMA defer_foreign_keys = ON;")
                .await?;
        }
    }
    Ok(())
}

pub(crate) async fn enable_foreign_key_checks(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    match manager.supported_db_type() {
        SupportedDbType::MySql => {
            manager
                .get_connection()
                .execute_unprepared("SET FOREIGN_KEY_CHECKS=1;")
                .await?;
        }
        SupportedDbType::Postgres => {
            // No-op because Postgres doesn't support disabling foreign key constraints globally.
        }
        SupportedDbType::Sqlite => {
            manager
                .get_connection()
                .execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
                .await?;
        }
    }
    Ok(())
}
