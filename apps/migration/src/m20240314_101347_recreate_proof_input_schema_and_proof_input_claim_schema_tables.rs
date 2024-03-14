use sea_orm_migration::prelude::*;

use crate::m20240110_000001_initial::{ClaimSchema, CredentialSchema, CustomDateTime, ProofSchema};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let datetime = CustomDateTime(manager.get_database_backend());

        manager
            .drop_table(Table::drop().table(ProofInputClaimSchema::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(ProofInputSchema::Table).to_owned())
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(ProofInputSchema::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ProofInputSchema::Id)
                            .big_integer()
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
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(ColumnDef::new(ProofInputSchema::ValidityConstraint).big_integer())
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
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(ProofInputClaimSchema::Table)
                    .col(
                        ColumnDef::new(ProofInputClaimSchema::ClaimSchemaId)
                            .char_len(36)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ProofInputClaimSchema::ProofInputSchemaId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ProofInputClaimSchema::Order)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(ProofInputClaimSchema::Required)
                            .boolean()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .name("pk-ProofInputClaimSchema")
                            .col(ProofInputClaimSchema::ClaimSchemaId)
                            .col(ProofInputClaimSchema::ProofInputSchemaId)
                            .primary(),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-ProofInputClaimSchema-ClaimSchemaId")
                            .from_tbl(ProofInputClaimSchema::Table)
                            .from_col(ProofInputClaimSchema::ClaimSchemaId)
                            .to_tbl(ClaimSchema::Table)
                            .to_col(ClaimSchema::Id),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-ProofInputClaimSchema-ProofSchemaId")
                            .from_tbl(ProofInputClaimSchema::Table)
                            .from_col(ProofInputClaimSchema::ProofInputSchemaId)
                            .to_tbl(ProofInputSchema::Table)
                            .to_col(ProofInputSchema::Id),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Err(DbErr::Migration(
            "BigUnsigned N/A for sqlite and postgres (breaks during runtime)".to_owned(),
        ))
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

#[derive(DeriveIden)]
pub enum ProofInputClaimSchema {
    Table,
    ClaimSchemaId,
    ProofInputSchemaId,
    Order,
    Required,
}
