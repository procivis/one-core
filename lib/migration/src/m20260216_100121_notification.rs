use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

use crate::datatype::{ColumnDefExt, timestamp, uuid_char};
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
                    .table(Notification::Table)
                    .col(uuid_char(Notification::Id).primary_key())
                    .col(text(Notification::Url))
                    .col(
                        ColumnDef::new(Notification::Payload)
                            .large_blob(manager)
                            .not_null(),
                    )
                    .col(timestamp(Notification::CreatedDate, manager))
                    .col(timestamp(Notification::NextTryDate, manager))
                    .col(unsigned(Notification::TriesCount))
                    .col(string(Notification::Type))
                    .col(string_null(Notification::HistoryTarget))
                    .col(uuid_char(Notification::OrganisationId))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-Notification-OrganisationId")
                            .from_tbl(Notification::Table)
                            .from_col(Notification::OrganisationId)
                            .to_tbl(Organisation::Table)
                            .to_col(Organisation::Id),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("index-Notification-CreatedDate")
                    .table(Notification::Table)
                    .col(Notification::CreatedDate)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("index-Notification-Type_NextTryDate")
                    .table(Notification::Table)
                    .col(Notification::Type)
                    .col(Notification::NextTryDate)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Notification {
    Table,
    Id,
    Url,
    Payload,
    CreatedDate,
    NextTryDate,
    TriesCount,
    Type,
    HistoryTarget,
    OrganisationId,
}
