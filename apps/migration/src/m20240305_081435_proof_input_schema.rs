use sea_orm_migration::prelude::*;

use crate::m20240110_000001_initial::{CredentialSchema, CustomDateTime, ProofSchema};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let datetime = CustomDateTime(manager.get_database_backend());

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
                            .custom(datetime)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ProofInputSchema::LastModified)
                            .custom(datetime)
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

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ProofInputSchema::Table).to_owned())
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
