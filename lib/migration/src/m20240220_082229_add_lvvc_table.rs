use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;
use crate::m20240110_000001_initial::Credential;

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
            .create_table(
                Table::create()
                    .table(Lvvc::Table)
                    .col(
                        ColumnDef::new(Lvvc::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Lvvc::CreatedDate)
                            .datetime_millisecond_precision(manager)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Lvvc::Credential)
                            .large_blob(manager)
                            .not_null(),
                    )
                    .col(ColumnDef::new(Lvvc::CredentialId).char_len(36).not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-Lvvc-CredentialId")
                            .from_tbl(Lvvc::Table)
                            .from_col(Lvvc::CredentialId)
                            .to_tbl(Credential::Table)
                            .to_col(Credential::Id),
                    )
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
pub(crate) enum Lvvc {
    Table,
    Id,
    CreatedDate,
    Credential,
    CredentialId,
}
