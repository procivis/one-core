use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::unsigned;

use crate::datatype::{timestamp, uuid_char};
use crate::m20240110_000001_initial::{CredentialSchema, ProofSchema};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DatabaseBackend::Postgres => {}
            DatabaseBackend::MySql => {
                // correct type
                manager
                    .alter_table(
                        Table::alter()
                            .table(ProofInputSchema::Table)
                            .modify_column(
                                ColumnDef::new(ProofInputSchema::Order)
                                    .unsigned()
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
enum ProofInputSchemaNew {
    Table,
}

#[derive(Clone, Iden)]
enum ProofInputSchema {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Order,
    ValidityConstraint,
    CredentialSchema,
    ProofSchema,
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();

    db.execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    // Create new table with the correct columns
    manager
        .create_table(
            Table::create()
                .table(ProofInputSchemaNew::Table)
                .col(
                    ColumnDef::new(ProofInputSchema::Id)
                        .big_integer()
                        .not_null()
                        .auto_increment()
                        .primary_key(),
                )
                .col(timestamp(ProofInputSchema::CreatedDate, manager))
                .col(timestamp(ProofInputSchema::LastModified, manager))
                .col(unsigned(ProofInputSchema::Order))
                .col(
                    ColumnDef::new(ProofInputSchema::ValidityConstraint)
                        .big_integer()
                        .null(),
                )
                .col(uuid_char(ProofInputSchema::CredentialSchema))
                .col(uuid_char(ProofInputSchema::ProofSchema))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-ProofInputSchema-CredentialSchema")
                        .from_tbl(ProofInputSchemaNew::Table)
                        .from_col(ProofInputSchema::CredentialSchema)
                        .to_tbl(CredentialSchema::Table)
                        .to_col(CredentialSchema::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-ProofInputSchema-ProofSchema")
                        .from_tbl(ProofInputSchemaNew::Table)
                        .from_col(ProofInputSchema::ProofSchema)
                        .to_tbl(ProofSchema::Table)
                        .to_col(ProofSchema::Id),
                )
                .to_owned(),
        )
        .await?;

    // Copy data from old table to new table
    let copied_columns = vec![
        ProofInputSchema::Id,
        ProofInputSchema::CreatedDate,
        ProofInputSchema::LastModified,
        ProofInputSchema::Order,
        ProofInputSchema::ValidityConstraint,
        ProofInputSchema::CredentialSchema,
        ProofInputSchema::ProofSchema,
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(ProofInputSchemaNew::Table)
                .columns(copied_columns.to_vec())
                .select_from(
                    Query::select()
                        .from(ProofInputSchema::Table)
                        .columns(copied_columns)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    // Drop old table & rename new table
    manager
        .drop_table(Table::drop().table(ProofInputSchema::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(ProofInputSchemaNew::Table, ProofInputSchema::Table)
                .to_owned(),
        )
        .await?;

    db.execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}
