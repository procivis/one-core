use sea_orm_migration::prelude::*;

use crate::m20230530_000001_initial::{CredentialSchema, ProofSchema};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Organisation::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Organisation::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Organisation::CreatedDate)
                            .date_time()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Organisation::LastModified)
                            .date_time()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(CredentialSchema::Table)
                    .add_foreign_key(
                        TableForeignKey::new()
                            .name("fk-CredentialSchema-OrganisationId")
                            .from_tbl(CredentialSchema::Table)
                            .from_col(CredentialSchema::OrganisationId)
                            .to_tbl(Organisation::Table)
                            .to_col(Organisation::Id),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(ProofSchema::Table)
                    .add_foreign_key(
                        TableForeignKey::new()
                            .name("fk-ProofSchema-OrganisationId")
                            .from_tbl(ProofSchema::Table)
                            .from_col(ProofSchema::OrganisationId)
                            .to_tbl(Organisation::Table)
                            .to_col(Organisation::Id),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ProofSchema::Table)
                    .drop_foreign_key(Alias::new("fk-ProofSchema-OrganisationId"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(CredentialSchema::Table)
                    .drop_foreign_key(Alias::new("fk-CredentialSchema-OrganisationId"))
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(Table::drop().table(Organisation::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(Iden)]
pub enum Organisation {
    Table,
    Id,
    CreatedDate,
    LastModified,
}
