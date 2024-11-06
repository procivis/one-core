use sea_orm_migration::prelude::*;

use crate::m20240110_000001_initial::ClaimSchema;
use crate::m20240305_081435_proof_input_schema::ProofInputSchema;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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
                            .big_unsigned()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ProofInputClaimSchema::Order)
                            .unsigned()
                            .not_null()
                            .default(0),
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
}

#[derive(DeriveIden)]
pub enum ProofInputClaimSchema {
    Table,
    ClaimSchemaId,
    ProofInputSchemaId,
    Order,
}
