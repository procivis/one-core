use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

use crate::datatype::{timestamp, uuid_char};
use crate::m20240110_000001_initial::Organisation;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DatabaseBackend::Postgres {
            return Ok(());
        }

        manager
            .create_table(
                Table::create()
                    .table(VerifierInstance::Table)
                    .col(uuid_char(VerifierInstance::Id).primary_key())
                    .col(timestamp(VerifierInstance::CreatedDate, manager))
                    .col(timestamp(VerifierInstance::LastModified, manager))
                    .col(string(VerifierInstance::ProviderUrl))
                    .col(string(VerifierInstance::ProviderName))
                    .col(string(VerifierInstance::ProviderType))
                    .col(uuid_char(VerifierInstance::OrganisationId))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-VerifierInstance-Organisation")
                            .from_tbl(VerifierInstance::Table)
                            .from_col(VerifierInstance::OrganisationId)
                            .to_tbl(Organisation::Table)
                            .to_col(Organisation::Id),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .unique()
                    .name("index-VerifierInstance-OrganisationId-Unique")
                    .table(VerifierInstance::Table)
                    .col(VerifierInstance::OrganisationId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum VerifierInstance {
    Table,
    Id,
    CreatedDate,
    LastModified,
    ProviderUrl,
    ProviderType,
    ProviderName,
    OrganisationId,
}
