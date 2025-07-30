use sea_orm_migration::prelude::*;

use crate::m20240110_000001_initial::{Did, UNIQUE_DID_DID_INDEX};

#[derive(DeriveMigrationName)]
pub struct Migration;

pub const UNIQUE_DID_DID_IN_ORGANISATION_INDEX: &str = "index-Did-Did-OrganisationId-Unique";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Postgres {
            // Skip because it is not supported. If support for Postgres is added in the future
            // the schema can be setup in its entirety in a new, later migration.
            return Ok(());
        }
        manager
            .drop_index(
                Index::drop()
                    .name(UNIQUE_DID_DID_INDEX)
                    .table(Did::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name(UNIQUE_DID_DID_IN_ORGANISATION_INDEX)
                    .unique()
                    .table(Did::Table)
                    .col(Did::Did)
                    .col(Did::OrganisationId)
                    .to_owned(),
            )
            .await
    }
}
