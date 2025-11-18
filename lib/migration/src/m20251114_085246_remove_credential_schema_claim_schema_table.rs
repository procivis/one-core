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
                        .null(), // add as nullable so we can copy data first
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

    manager
        .exec_stmt(
            Query::update()
                .table(ClaimSchema::Table)
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
        .await?;

    // Now that data has been copied, make the column non-NULL
    manager
        .alter_table(
            Table::alter()
                .table(ClaimSchema::Table)
                .modify_column(
                    ColumnDef::new(ClaimSchema::CredentialSchemaId)
                        .char_len(36)
                        .not_null(),
                )
                .to_owned(),
        )
        .await?;

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
                        .not_null(),
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

    manager
        .exec_stmt(
            Query::insert()
                .into_table(ClaimSchemaNew::Table)
                .columns(vec![
                    ClaimSchema::Id,
                    ClaimSchema::Key,
                    ClaimSchema::Datatype,
                    ClaimSchema::CreatedDate,
                    ClaimSchema::LastModified,
                    ClaimSchema::Array,
                    ClaimSchema::Metadata,
                    ClaimSchema::CredentialSchemaId,
                    ClaimSchema::Required,
                    ClaimSchema::Order,
                ])
                .select_from(
                    Query::select()
                        .from(ClaimSchema::Table)
                        .columns(vec![
                            ClaimSchema::Id,
                            ClaimSchema::Key,
                            ClaimSchema::Datatype,
                            ClaimSchema::CreatedDate,
                            ClaimSchema::LastModified,
                            ClaimSchema::Array,
                            ClaimSchema::Metadata,
                        ])
                        .join(
                            JoinType::Join,
                            CredentialSchemaClaimSchema::Table,
                            Expr::col(ClaimSchema::Id).eq(Expr::col((
                                CredentialSchemaClaimSchema::Table,
                                CredentialSchemaClaimSchema::ClaimSchemaId,
                            ))),
                        )
                        .columns(vec![
                            CredentialSchemaClaimSchema::CredentialSchemaId,
                            CredentialSchemaClaimSchema::Required,
                            CredentialSchemaClaimSchema::Order,
                        ])
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

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
