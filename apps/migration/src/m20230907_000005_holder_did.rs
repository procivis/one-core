use crate::m20230530_000001_initial::{Credential as OldCredential, Proof as OldProof};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(OldProof::Table)
                    .rename_column(OldProof::ReceiverDidId, Proof::HolderDidId)
                    // leaving foreign key definition intact for simplicity (only rename needed anyway), since SQLite doesn't support modifications
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(OldCredential::Table)
                    .rename_column(OldCredential::ReceiverDidId, Credential::HolderDidId)
                    // leaving foreign key definition intact for simplicity (only rename needed anyway), since SQLite doesn't support modifications
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(OldProof::Table)
                    .rename_column(Proof::HolderDidId, OldProof::ReceiverDidId)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(OldCredential::Table)
                    .rename_column(Credential::HolderDidId, OldCredential::ReceiverDidId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(Iden)]
pub enum Proof {
    HolderDidId,
}

#[derive(Iden)]
pub enum Credential {
    HolderDidId,
}
