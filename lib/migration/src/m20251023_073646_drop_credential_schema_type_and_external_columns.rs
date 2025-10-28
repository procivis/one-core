use sea_orm::{DatabaseBackend, DbBackend};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DbBackend::Postgres => Ok(()),
            DatabaseBackend::MySql => mysql_migration(manager).await,
            DatabaseBackend::Sqlite => sqlite_migration(manager).await,
        }
    }
}

async fn mysql_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_index(
            Index::create()
                .name("index-Organisation-SchemaId-DeletedAt_Unique")
                .table(CredentialSchema::Table)
                .col(CredentialSchema::OrganisationId)
                .col(CredentialSchema::SchemaId)
                .col(CredentialSchema::DeletedAtMaterialized)
                .unique()
                .to_owned(),
        )
        .await?;
    manager
        .drop_index(
            Index::drop()
                .table(CredentialSchema::Table)
                .name("index-SchemaId-Organisation-SchemaType-DeletedAt_Unique")
                .to_owned(),
        )
        .await?;
    manager
        .alter_table(
            Table::alter()
                .table(CredentialSchema::Table)
                .drop_column(CredentialSchema::SchemaType)
                .drop_column(CredentialSchema::ExternalSchema)
                .to_owned(),
        )
        .await?;
    Ok(())
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .drop_index(
            Index::drop()
                .if_exists()
                .table(CredentialSchema::Table)
                .name("index-SchemaId-Organisation-SchemaType-DeletedAt_Unique")
                .to_owned(),
        )
        .await?;
    manager
        .alter_table(
            Table::alter()
                .table(CredentialSchema::Table)
                .drop_column(CredentialSchema::SchemaType)
                .to_owned(),
        )
        .await?;
    manager
        .alter_table(
            Table::alter()
                .table(CredentialSchema::Table)
                .drop_column(CredentialSchema::ExternalSchema)
                .to_owned(),
        )
        .await?;
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
    Ok(())
}

#[derive(DeriveIden, Clone, Copy)]
enum CredentialSchema {
    Table,
    SchemaType,
    ExternalSchema,
    SchemaId,
    OrganisationId,
    DeletedAtMaterialized,
}
