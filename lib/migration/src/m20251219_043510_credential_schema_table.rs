use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{boolean, string, string_null};

use crate::datatype::{timestamp, timestamp_null, uuid_char};
use crate::m20240110_000001_initial::Organisation;

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
                            .table(CredentialSchema::Table)
                            .modify_column(
                                ColumnDef::new(CredentialSchema::SchemaId)
                                    .string()
                                    .not_null(),
                            )
                            .modify_column(
                                ColumnDef::new(CredentialSchema::ImportedSourceUrl)
                                    .string()
                                    .not_null(),
                            )
                            .modify_column(
                                ColumnDef::new(CredentialSchema::AllowSuspension)
                                    .boolean()
                                    .not_null(),
                            )
                            .modify_column(
                                ColumnDef::new(CredentialSchema::RequiresAppAttestation)
                                    .boolean()
                                    .not_null(),
                            )
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
enum CredentialSchemaNew {
    Table,
}

#[derive(Clone, Iden)]
enum CredentialSchema {
    Table,
    Id,
    CreatedDate,
    LastModified,
    DeletedAt,
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

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();

    db.execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    // Create new table with the correct columns
    manager
        .create_table(
            Table::create()
                .table(CredentialSchemaNew::Table)
                .col(uuid_char(CredentialSchema::Id).primary_key())
                .col(timestamp(CredentialSchema::CreatedDate, manager))
                .col(timestamp(CredentialSchema::LastModified, manager))
                .col(timestamp_null(CredentialSchema::DeletedAt, manager))
                .col(string(CredentialSchema::Name))
                .col(string(CredentialSchema::Format))
                .col(string(CredentialSchema::RevocationMethod))
                .col(uuid_char(CredentialSchema::OrganisationId))
                .col(string(CredentialSchema::SchemaId))
                .col(
                    ColumnDef::new(CredentialSchema::LayoutProperties)
                        .json()
                        .null(),
                )
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
                .to_owned(),
        )
        .await?;

    // Copy data from old table to new table
    let copied_columns = vec![
        CredentialSchema::Id,
        CredentialSchema::CreatedDate,
        CredentialSchema::LastModified,
        CredentialSchema::DeletedAt,
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

    // Recreate indexes
    manager
        .get_connection()
        .execute_unprepared(
            r#"
            CREATE UNIQUE INDEX `index-Organisation-SchemaId-DeletedAt_Unique`
            ON credential_schema(
                `organisation_id`,
                `schema_id`,
                COALESCE(deleted_at, 'not_deleted')
            );
            "#,
        )
        .await?;

    manager
        .get_connection()
        .execute_unprepared(
            r#"
            CREATE UNIQUE INDEX `index_CredentialSchema_Name-OrganisationId-DeletedAt_Unique`
            ON credential_schema(
                `name`,
                `organisation_id`,
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

    db.execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}
