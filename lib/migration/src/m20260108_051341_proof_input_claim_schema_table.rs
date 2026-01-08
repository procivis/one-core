use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{boolean, unsigned};

use crate::datatype::uuid_char;
use crate::m20240110_000001_initial::ClaimSchema;
use crate::m20240305_081435_proof_input_schema::ProofInputSchema;

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
                            .table(ProofInputClaimSchema::Table)
                            .modify_column(
                                ColumnDef::new(ProofInputClaimSchema::Order)
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
enum ProofInputClaimSchemaNew {
    Table,
}

#[derive(Clone, Iden)]
enum ProofInputClaimSchema {
    Table,
    ClaimSchemaId,
    ProofInputSchemaId,
    Order,
    Required,
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();

    db.execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    // Create new table with the correct columns
    manager
        .create_table(
            Table::create()
                .table(ProofInputClaimSchemaNew::Table)
                .col(uuid_char(ProofInputClaimSchema::ClaimSchemaId))
                .col(
                    ColumnDef::new(ProofInputClaimSchema::ProofInputSchemaId)
                        .big_integer()
                        .not_null(),
                )
                .col(unsigned(ProofInputClaimSchema::Order))
                .col(boolean(ProofInputClaimSchema::Required))
                .primary_key(
                    Index::create()
                        .name("pk-ProofInputClaimSchema")
                        .col(ProofInputClaimSchema::ClaimSchemaId)
                        .col(ProofInputClaimSchema::ProofInputSchemaId)
                        .primary(),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-ProofInputClaimSchema-ClaimSchemaId")
                        .from_tbl(ProofInputClaimSchemaNew::Table)
                        .from_col(ProofInputClaimSchema::ClaimSchemaId)
                        .to_tbl(ClaimSchema::Table)
                        .to_col(ClaimSchema::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-ProofInputClaimSchema-ProofSchemaId")
                        .from_tbl(ProofInputClaimSchemaNew::Table)
                        .from_col(ProofInputClaimSchema::ProofInputSchemaId)
                        .to_tbl(ProofInputSchema::Table)
                        .to_col(ProofInputSchema::Id),
                )
                .to_owned(),
        )
        .await?;

    // Copy data from old table to new table
    let copied_columns = vec![
        ProofInputClaimSchema::ClaimSchemaId,
        ProofInputClaimSchema::ProofInputSchemaId,
        ProofInputClaimSchema::Order,
        ProofInputClaimSchema::Required,
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(ProofInputClaimSchemaNew::Table)
                .columns(copied_columns.to_vec())
                .select_from(
                    Query::select()
                        .from(ProofInputClaimSchema::Table)
                        .columns(copied_columns)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    // Drop old table & rename new table
    manager
        .drop_table(Table::drop().table(ProofInputClaimSchema::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(
                    ProofInputClaimSchemaNew::Table,
                    ProofInputClaimSchema::Table,
                )
                .to_owned(),
        )
        .await?;

    db.execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}
