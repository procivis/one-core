use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{boolean, json_null, string, string_null};

use crate::datatype::{timestamp, timestamp_null, uuid_char};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DbBackend::Postgres => return Ok(()),
            DbBackend::Sqlite => alter_tables_sqlite(manager).await,
            DbBackend::MySql => alter_tables_mysql(manager).await,
        }?;
        migrate_columns(manager).await
    }
}

async fn alter_tables_mysql(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(CredentialSchema::Table)
                .modify_column(
                    ColumnDef::new(CredentialSchema::RevocationMethod)
                        .string()
                        .null(),
                )
                .to_owned(),
        )
        .await?;

    Ok(())
}

async fn alter_tables_sqlite(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();

    // Disable foreign keys for SQLite
    db.execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    // Create new table with the additional column
    manager
        .create_table(
            Table::create()
                .table(CredentialSchemaNew::Table)
                .col(uuid_char(CredentialSchema::Id).primary_key())
                .col(timestamp_null(CredentialSchema::DeletedAt, manager))
                .col(timestamp(CredentialSchema::CreatedDate, manager))
                .col(timestamp(CredentialSchema::LastModified, manager))
                .col(string(CredentialSchema::Name))
                .col(string(CredentialSchema::Format))
                .col(string_null(CredentialSchema::RevocationMethod))
                .col(uuid_char(CredentialSchema::OrganisationId))
                .col(string(CredentialSchema::SchemaId))
                .col(json_null(CredentialSchema::LayoutProperties))
                .col(string(CredentialSchema::LayoutType))
                .col(string(CredentialSchema::ImportedSourceUrl))
                .col(boolean(CredentialSchema::AllowSuspension))
                .col(boolean(CredentialSchema::RequiresAppAttestation))
                .col(string_null(CredentialSchema::KeyStorageSecurity))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-CredentialSchema-OrganisationId")
                        .from_tbl(CredentialSchemaNew::Table)
                        .from_col(CredentialSchema::OrganisationId)
                        .to_tbl(Organisation::Table)
                        .to_col(Organisation::Id),
                )
                .take(),
        )
        .await?;

    // Copy data from old table to new table
    let copied_columns = vec![
        CredentialSchema::Id,
        CredentialSchema::DeletedAt,
        CredentialSchema::CreatedDate,
        CredentialSchema::LastModified,
        CredentialSchema::Name,
        CredentialSchema::Format,
        CredentialSchema::RevocationMethod,
        CredentialSchema::OrganisationId,
        CredentialSchema::SchemaId,
        CredentialSchema::LayoutProperties,
        CredentialSchema::LayoutType,
        CredentialSchema::ImportedSourceUrl,
        CredentialSchema::AllowSuspension,
        CredentialSchema::RequiresAppAttestation,
        CredentialSchema::KeyStorageSecurity,
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(CredentialSchemaNew::Table)
                .columns(copied_columns.to_vec())
                .select_from(
                    Query::select()
                        .from(CredentialSchema::Table)
                        .columns(copied_columns)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    // Drop old table & rename new table
    manager
        .drop_table(Table::drop().table(CredentialSchema::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(CredentialSchemaNew::Table, CredentialSchema::Table)
                .to_owned(),
        )
        .await?;

    // Recreate indices
    manager
        .get_connection()
        .execute_unprepared(
            r#"
            CREATE UNIQUE INDEX "index_CredentialSchema_Name-OrganisationId-DeletedAt_Unique"
            ON "credential_schema"(
                "name",
                "organisation_id",
                COALESCE(deleted_at, 'not_deleted')
            );
            "#,
        )
        .await?;

    manager
        .get_connection()
        .execute_unprepared(
            r#"
            CREATE UNIQUE INDEX "index-Organisation-SchemaId-DeletedAt_Unique"
            ON "credential_schema"(
                "organisation_id",
                "schema_id",
                COALESCE(deleted_at, 'not_deleted')
            );
            "#,
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-CredentialSchema-CreatedDate")
                .table(CredentialSchema::Table)
                .col(CredentialSchema::CreatedDate)
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

async fn migrate_columns(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .exec_stmt(
            Query::update()
                .table(CredentialSchema::Table)
                .value(CredentialSchema::RevocationMethod, Keyword::Null)
                .and_where(Expr::col(CredentialSchema::RevocationMethod).eq("NONE"))
                .to_owned(),
        )
        .await?;

    Ok(())
}

#[derive(Clone, DeriveIden)]
pub enum CredentialSchema {
    Table,
    Id,
    DeletedAt,
    CreatedDate,
    LastModified,
    Name,
    Format,
    RevocationMethod,
    OrganisationId,
    SchemaId,
    LayoutProperties,
    LayoutType,
    ImportedSourceUrl,
    AllowSuspension,
    RequiresAppAttestation,
    KeyStorageSecurity,
}

#[derive(Clone, DeriveIden)]
pub enum CredentialSchemaNew {
    Table,
}

#[derive(Clone, DeriveIden)]
pub enum Organisation {
    Table,
    Id,
}
