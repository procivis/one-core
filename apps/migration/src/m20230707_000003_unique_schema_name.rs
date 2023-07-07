use sea_orm_migration::prelude::*;

use crate::m20230530_000001_initial::{CredentialSchema, ProofSchema};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .name("index-CredentialSchema-Name-Unique")
                    .unique()
                    .table(CredentialSchema::Table)
                    .col(CredentialSchema::OrganisationId)
                    .col(CredentialSchema::Name)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("index-ProofSchema-Name-Unique")
                    .unique()
                    .table(ProofSchema::Table)
                    .col(ProofSchema::OrganisationId)
                    .col(ProofSchema::Name)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("index-ProofSchema-Name-Unique")
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("index-CredentialSchema-Name-Unique")
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
