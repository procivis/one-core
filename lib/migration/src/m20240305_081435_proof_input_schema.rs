use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;
use crate::m20240110_000001_initial::{CredentialSchema, ProofSchema};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Postgres {
            // Skip because it is not supported. If support for Postgres is added in the future
            // the schema can be setup in its entirety in a new, later migration.
            return Ok(());
        }
        manager
            .create_table(
                Table::create()
                    .table(ProofInputSchema::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ProofInputSchema::Id)
                            .big_unsigned()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(ProofInputSchema::CreatedDate)
                            .datetime_millisecond_precision(manager)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ProofInputSchema::LastModified)
                            .datetime_millisecond_precision(manager)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ProofInputSchema::Order)
                            .unsigned()
                            .not_null()
                            .default(0),
                    )
                    .col(ColumnDef::new(ProofInputSchema::ValidityConstraint).big_unsigned())
                    .col(
                        ColumnDef::new(ProofInputSchema::CredentialSchema)
                            .char_len(36)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ProofInputSchema::ProofSchema)
                            .char_len(36)
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-ProofInputSchema-CredentialSchema")
                            .from_tbl(ProofInputSchema::Table)
                            .from_col(ProofInputSchema::CredentialSchema)
                            .to_tbl(CredentialSchema::Table)
                            .to_col(CredentialSchema::Id),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-ProofInputSchema-ProofSchema")
                            .from_tbl(ProofInputSchema::Table)
                            .from_col(ProofInputSchema::ProofSchema)
                            .to_tbl(ProofSchema::Table)
                            .to_col(ProofSchema::Id),
                    )
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
pub enum ProofInputSchema {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Order,
    ValidityConstraint,
    CredentialSchema,
    ProofSchema,
}
