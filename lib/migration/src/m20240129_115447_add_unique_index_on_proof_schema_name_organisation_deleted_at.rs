use sea_orm_migration::prelude::*;

use crate::m20240110_000001_initial::{
    ProofSchema, UNIQUE_PROOF_SCHEMA_ORGANISATION_ID_NAME_INDEX,
};

pub const UNIQUE_INDEX_PROOF_SCHEMA_ORGANISATION_ID_NAME_DELETED_AT: &str =
    "index-ProofSchema-OrganisationId-Name-DeletedAt_Unique";

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
}
