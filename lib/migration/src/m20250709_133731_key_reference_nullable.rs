use sea_orm::{DatabaseBackend, DbBackend, ExecResult};
use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;
use crate::m20240110_000001_initial::Organisation;

#[derive(DeriveMigrationName)]
pub struct Migration;

const UNIQUE_KEY_NAME_ORGANISATION_DELETED_AT_INDEX: &str =
    "index_Key_Name-OrganisationId-DeletedAt_Unique";

const KEY_CREATED_DATE_INDEX: &str = "index-Key-CreatedDate";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DbBackend::MySql | DbBackend::Postgres => {
                manager
                    .alter_table(
                        Table::alter()
                            .table(Key::Table)
                            .modify_column(
                                ColumnDef::new(Key::KeyReference).large_blob(manager).null(),
                            )
                            .to_owned(),
                    )
                    .await
            }
            DbBackend::Sqlite => sqlite_migration(manager).await,
        }
    }
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(NewKey::Table)
                .col(
                    ColumnDef::new(NewKey::Id)
                        .char_len(36)
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(NewKey::CreatedDate)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(NewKey::LastModified)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(ColumnDef::new(NewKey::Name).string().not_null())
                .col(
                    ColumnDef::new(NewKey::PublicKey)
                        .large_blob(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(NewKey::KeyReference)
                        .large_blob(manager)
                        .null(),
                )
                .col(ColumnDef::new(NewKey::StorageType).string().not_null())
                .col(ColumnDef::new(NewKey::KeyType).string().not_null())
                .col(
                    ColumnDef::new(NewKey::OrganisationId)
                        .char_len(36)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(NewKey::DeletedAt)
                        .datetime_millisecond_precision(manager)
                        .null(),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk-Key-OrganisationId")
                        .from_tbl(NewKey::Table)
                        .from_col(NewKey::OrganisationId)
                        .to_tbl(Organisation::Table)
                        .to_col(Organisation::Id),
                )
                .to_owned(),
        )
        .await?;

    manager
        .drop_index(
            Index::drop()
                .table(Key::Table)
                .name(UNIQUE_KEY_NAME_ORGANISATION_DELETED_AT_INDEX)
                .to_owned(),
        )
        .await?;
    manager
        .drop_index(
            Index::drop()
                .table(Key::Table)
                .name(KEY_CREATED_DATE_INDEX)
                .to_owned(),
        )
        .await?;

    let copied_columns = [
        NewKey::Id,
        NewKey::CreatedDate,
        NewKey::LastModified,
        NewKey::Name,
        NewKey::PublicKey,
        NewKey::StorageType,
        NewKey::KeyReference,
        NewKey::KeyType,
        NewKey::OrganisationId,
        NewKey::DeletedAt,
    ];

    manager
        .exec_stmt(
            Query::insert()
                .into_table(NewKey::Table)
                .columns(copied_columns)
                .select_from(
                    Query::select()
                        .from(Key::Table)
                        .columns(copied_columns)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    // Disable foreign keys for SQLite
    manager
        .get_connection()
        .execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    manager
        .drop_table(Table::drop().table(Key::Table).to_owned())
        .await?;

    manager
        .rename_table(Table::rename().table(NewKey::Table, Key::Table).to_owned())
        .await?;

    manager
        .create_index(
            Index::create()
                .name(KEY_CREATED_DATE_INDEX)
                .table(Key::Table)
                .col(NewKey::CreatedDate)
                .to_owned(),
        )
        .await?;

    add_unique_index_with_deleted_at_materialized_dependency(
        UNIQUE_KEY_NAME_ORGANISATION_DELETED_AT_INDEX,
        Key::Table,
        (NewKey::Name, NewKey::OrganisationId),
        manager,
    )
    .await?;

    // Enable foreign keys for SQLite
    manager
        .get_connection()
        .execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}

async fn add_unique_index_with_deleted_at_materialized_dependency(
    index_name: &str,
    table: impl IntoIden,
    other_colums: impl IdenList,
    manager: &SchemaManager<'_>,
) -> Result<ExecResult, DbErr> {
    let table = table.into_iden().to_string();
    let other_columns = other_colums
        .into_iter()
        .map(|column| format!("`{}`", column.to_string()))
        .collect::<Vec<_>>()
        .join(",");

    let query = match manager.get_database_backend() {
        DatabaseBackend::MySql => {
            format!(
                "CREATE UNIQUE INDEX `{index_name}` ON `{table}`({other_columns},`deleted_at_materialized`);",
            )
        }
        DatabaseBackend::Sqlite => {
            format!(
                "CREATE UNIQUE INDEX `{index_name}` ON `{table}`({other_columns},COALESCE(deleted_at, 'not_deleted'));",
            )
        }
        backend => unimplemented!("Not implemented for: {backend:?}"),
    };

    manager.get_connection().execute_unprepared(&query).await
}

#[derive(DeriveIden)]
enum Key {
    Table,
    KeyReference,
}

#[derive(DeriveIden, Clone, Copy)]
pub enum NewKey {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Name,
    PublicKey,
    StorageType,
    KeyReference,
    KeyType,
    OrganisationId,
    DeletedAt,
}
