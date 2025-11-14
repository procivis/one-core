use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;
use crate::m20240110_000001_initial::{CredentialSchema, CredentialSchemaClaimSchema};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DbBackend::Postgres => Ok(()),
            DbBackend::Sqlite => sqlite_migration(manager).await,
            DbBackend::MySql => simple_migration(manager).await,
        }
    }
}

async fn simple_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(ClaimSchema::Table)
                .add_column(
                    ColumnDef::new(ClaimSchema::CredentialSchemaId)
                        .char_len(36)
                        .null(),
                )
                .add_column(
                    ColumnDef::new(ClaimSchema::Required)
                        .boolean()
                        .default(false)
                        .not_null(),
                )
                .add_column(
                    ColumnDef::new(ClaimSchema::Order)
                        .unsigned()
                        .default(0)
                        .not_null(),
                )
                .add_foreign_key(
                    TableForeignKey::new()
                        .name("fk_claim_schema_credential_schema_id")
                        .from_tbl(ClaimSchema::Table)
                        .from_col(ClaimSchema::CredentialSchemaId)
                        .to_tbl(CredentialSchema::Table)
                        .to_col(CredentialSchema::Id),
                )
                .to_owned(),
        )
        .await?;

    copy_data_from_credential_schema_claim_schema(manager, ClaimSchema::Table).await?;
    drop_credential_schema_claim_schema(manager).await?;

    Ok(())
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(ClaimSchemaNew::Table)
                .col(
                    ColumnDef::new(ClaimSchema::Id)
                        .char_len(36)
                        .not_null()
                        .primary_key(),
                )
                .col(ColumnDef::new(ClaimSchema::Key).string().not_null())
                .col(ColumnDef::new(ClaimSchema::Datatype).string().not_null())
                .col(
                    ColumnDef::new(ClaimSchema::CreatedDate)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ClaimSchema::LastModified)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ClaimSchema::Array)
                        .boolean()
                        .not_null()
                        .default(false),
                )
                .col(
                    ColumnDef::new(ClaimSchema::Metadata)
                        .boolean()
                        .not_null()
                        .default(false),
                )
                .col(
                    ColumnDef::new(ClaimSchema::CredentialSchemaId)
                        .char_len(36)
                        .null(),
                )
                .col(
                    ColumnDef::new(ClaimSchema::Required)
                        .boolean()
                        .default(false)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ClaimSchema::Order)
                        .unsigned()
                        .default(0)
                        .not_null(),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk_claim_schema_credential_schema_id")
                        .from_tbl(ClaimSchemaNew::Table)
                        .from_col(ClaimSchemaNew::CredentialSchemaId)
                        .to_tbl(CredentialSchema::Table)
                        .to_col(CredentialSchema::Id),
                )
                .to_owned(),
        )
        .await?;

    let copied_columns = vec![
        ClaimSchema::Id,
        ClaimSchema::Key,
        ClaimSchema::Datatype,
        ClaimSchema::CreatedDate,
        ClaimSchema::LastModified,
        ClaimSchema::Array,
        ClaimSchema::Metadata,
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
    copy_data_from_credential_schema_claim_schema(manager, ClaimSchemaNew::Table).await?;
    drop_credential_schema_claim_schema(manager).await?;

    // Disable foreign keys for SQLite
    manager
        .get_connection()
        .execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

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

    // Enable foreign keys for SQLite
    manager
        .get_connection()
        .execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}

async fn copy_data_from_credential_schema_claim_schema<T>(
    manager: &SchemaManager<'_>,
    target_table: T,
) -> Result<(), DbErr>
where
    T: IntoTableRef,
{
    manager
        .exec_stmt(
            Query::update()
                .table(target_table)
                .value(
                    ClaimSchema::CredentialSchemaId,
                    Expr::column((
                        CredentialSchemaClaimSchema::Table,
                        CredentialSchemaClaimSchema::CredentialSchemaId,
                    )),
                )
                .value(
                    ClaimSchema::Required,
                    Expr::column((
                        CredentialSchemaClaimSchema::Table,
                        CredentialSchemaClaimSchema::Required,
                    )),
                )
                .value(
                    ClaimSchema::Order,
                    Expr::column((
                        CredentialSchemaClaimSchema::Table,
                        CredentialSchemaClaimSchema::Order,
                    )),
                )
                .from(CredentialSchemaClaimSchema::Table)
                .cond_where(Expr::col(ClaimSchema::Id).eq(Expr::col((
                    CredentialSchemaClaimSchema::Table,
                    CredentialSchemaClaimSchema::ClaimSchemaId,
                ))))
                .to_owned(),
        )
        .await
}

async fn drop_credential_schema_claim_schema(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .drop_table(
            Table::drop()
                .table(CredentialSchemaClaimSchema::Table)
                .to_owned(),
        )
        .await
}

#[derive(Clone, Iden)]
pub enum ClaimSchema {
    Table,
    Id,
    Key,
    Datatype,
    CreatedDate,
    LastModified,
    Array,
    Metadata,
    CredentialSchemaId,
    Required,
    Order,
}

#[derive(Iden)]
pub enum ClaimSchemaNew {
    Table,
    CredentialSchemaId,
}
