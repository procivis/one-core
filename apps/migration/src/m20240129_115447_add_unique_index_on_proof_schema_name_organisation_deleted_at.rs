use sea_orm_migration::prelude::*;

use crate::m20240110_000001_initial::{
    ProofSchema, UNIQUE_PROOF_SCHEMA_ORGANISATION_ID_NAME_INDEX,
};

const UNIQUE_INDEX_PROOF_SCHEMA_ORGANISATION_ID_NAME_DELETED_AT: &str =
    "index-ProofSchema-OrganisationId-Name-DeletedAt_Unique";

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .unique()
                    .name(UNIQUE_INDEX_PROOF_SCHEMA_ORGANISATION_ID_NAME_DELETED_AT)
                    .table(ProofSchema::Table)
                    .col(ProofSchema::OrganisationId)
                    .col(ProofSchema::Name)
                    .col(ProofSchema::DeletedAt)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name(UNIQUE_PROOF_SCHEMA_ORGANISATION_ID_NAME_INDEX)
                    .table(ProofSchema::Table)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .unique()
                    .name(UNIQUE_PROOF_SCHEMA_ORGANISATION_ID_NAME_INDEX)
                    .table(ProofSchema::Table)
                    .col(ProofSchema::OrganisationId)
                    .col(ProofSchema::Name)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name(UNIQUE_INDEX_PROOF_SCHEMA_ORGANISATION_ID_NAME_DELETED_AT)
                    .table(ProofSchema::Table)
                    .to_owned(),
            )
            .await
    }
}
