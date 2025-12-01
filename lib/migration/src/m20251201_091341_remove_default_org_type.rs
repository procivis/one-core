use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{blob_null, string};

use crate::datatype::{timestamp, uuid_char, uuid_char_null};
use crate::m20240110_000001_initial::Organisation;
use crate::m20250919_095358_nonce_id::UNIQUE_INTERACTION_NONCE_ID_INDEX;
use crate::m20251014_101039_adds_interaction_type::Interaction;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DbBackend::Postgres => Ok(()),
            DbBackend::MySql => {
                manager
                    .alter_table(
                        Table::alter()
                            .table(Interaction::Table)
                            .modify_column(string(Interaction::InteractionType))
                            .to_owned(),
                    )
                    .await
            }
            DbBackend::Sqlite => sqlite_migration(manager).await,
        }
    }
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();

    // Disable foreign keys for SQLite
    db.execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    // Create new table with the modified column
    manager
        .create_table(
            Table::create()
                .table(InteractionCopy::Table)
                .col(uuid_char(InteractionCopy::Id).primary_key())
                .col(timestamp(InteractionCopy::CreatedDate, manager))
                .col(timestamp(InteractionCopy::LastModified, manager))
                .col(blob_null(InteractionCopy::Data))
                .col(uuid_char(InteractionCopy::OrganisationId))
                .col(uuid_char_null(InteractionCopy::NonceId))
                .col(string(InteractionCopy::InteractionType))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-interaction-OrganisationId")
                        .from_tbl(InteractionCopy::Table)
                        .from_col(InteractionCopy::OrganisationId)
                        .to_tbl(Organisation::Table)
                        .to_col(Organisation::Id),
                )
                .take(),
        )
        .await?;

    // Copy data from old table to new table
    let copied_columns = vec![
        InteractionCopy::Id,
        InteractionCopy::CreatedDate,
        InteractionCopy::LastModified,
        InteractionCopy::Data,
        InteractionCopy::OrganisationId,
        InteractionCopy::NonceId,
        InteractionCopy::InteractionType,
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(InteractionCopy::Table)
                .columns(copied_columns.to_vec())
                .select_from(
                    Query::select()
                        .from(Interaction::Table)
                        .columns(copied_columns)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    // Drop old table and rename new table
    manager
        .drop_table(Table::drop().table(Interaction::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(InteractionCopy::Table, Interaction::Table)
                .to_owned(),
        )
        .await?;

    // Recreate indexes
    manager
        .create_index(
            Index::create()
                .name(UNIQUE_INTERACTION_NONCE_ID_INDEX)
                .unique()
                .table(Interaction::Table)
                .col(InteractionCopy::NonceId)
                .to_owned(),
        )
        .await?;

    // Enable foreign keys for SQLite
    manager
        .get_connection()
        .execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;
    Ok(())
}

#[derive(DeriveIden, Clone)]
pub enum InteractionCopy {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Data,
    OrganisationId,
    NonceId,
    InteractionType,
}
