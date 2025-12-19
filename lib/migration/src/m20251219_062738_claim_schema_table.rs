use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{boolean, string};

use crate::datatype::{timestamp, uuid_char};
use crate::m20240110_000001_initial::CredentialSchema;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DatabaseBackend::Postgres => {}
            DatabaseBackend::MySql => {
                // remove default values
                manager
                    .alter_table(
                        Table::alter()
                            .table(ClaimSchema::Table)
                            .modify_column(ColumnDef::new(ClaimSchema::Array).boolean().not_null())
                            .modify_column(
                                ColumnDef::new(ClaimSchema::Metadata).boolean().not_null(),
                            )
                            .modify_column(
                                ColumnDef::new(ClaimSchema::Required).boolean().not_null(),
                            )
                            .modify_column(ColumnDef::new(ClaimSchema::Order).unsigned().not_null())
                            .to_owned(),
                    )
                    .await?;
            }
            DatabaseBackend::Sqlite => sqlite_migration(manager).await?,
        };

        Ok(())
    }
}

#[derive(Iden)]
enum ClaimSchemaNew {
    Table,
}

#[derive(Clone, Iden)]
enum ClaimSchema {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Key,
    Datatype,
    Array,
    Metadata,
    CredentialSchemaId,
    Required,
    Order,
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();

    db.execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    // Create new table with the correct columns
    manager
        .create_table(
            Table::create()
                .table(ClaimSchemaNew::Table)
                .col(uuid_char(ClaimSchema::Id).primary_key())
                .col(timestamp(ClaimSchema::CreatedDate, manager))
                .col(timestamp(ClaimSchema::LastModified, manager))
                .col(string(ClaimSchema::Key))
                .col(string(ClaimSchema::Datatype))
                .col(boolean(ClaimSchema::Array))
                .col(boolean(ClaimSchema::Metadata))
                .col(uuid_char(ClaimSchema::CredentialSchemaId))
                .col(boolean(ClaimSchema::Required))
                .col(ColumnDef::new(ClaimSchema::Order).unsigned().not_null())
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_claim_schema_credential_schema_id")
                        .from_tbl(ClaimSchemaNew::Table)
                        .from_col(ClaimSchema::CredentialSchemaId)
                        .to_tbl(CredentialSchema::Table)
                        .to_col(CredentialSchema::Id),
                )
                .to_owned(),
        )
        .await?;

    // Copy data from old table to new table
    let copied_columns = vec![
        ClaimSchema::Id,
        ClaimSchema::CreatedDate,
        ClaimSchema::LastModified,
        ClaimSchema::Key,
        ClaimSchema::Datatype,
        ClaimSchema::Array,
        ClaimSchema::Metadata,
        ClaimSchema::CredentialSchemaId,
        ClaimSchema::Required,
        ClaimSchema::Order,
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(ClaimSchemaNew::Table)
                .columns(copied_columns.to_vec())
                .select_from(
                    Query::select()
                        .from(ClaimSchema::Table)
                        .columns(copied_columns)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    // Drop old table & rename new table
    manager
        .drop_table(Table::drop().table(ClaimSchema::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(ClaimSchemaNew::Table, ClaimSchema::Table)
                .to_owned(),
        )
        .await?;

    db.execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}
