use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

use crate::m20240110_000001_initial::CustomDateTime;
use crate::ColumnDefExt;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

const TABLE: &str = "interaction";
const CREDENTIAL_TABLE: &str = "credential";
const PROOF_TABLE: &str = "proof";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(&format!(
                "UPDATE {} SET interaction_id=null",
                CREDENTIAL_TABLE
            ))
            .await?;
        manager
            .get_connection()
            .execute_unprepared(&format!("UPDATE {} SET interaction_id=null", PROOF_TABLE))
            .await?;
        manager
            .get_connection()
            .execute_unprepared(&format!("DELETE FROM {}", TABLE))
            .await?;

        match manager.get_database_backend() {
            DbBackend::MySql | DbBackend::Postgres => sane_migration(manager).await,
            DbBackend::Sqlite => sqlite_migration(manager).await,
        }
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new(TABLE))
                    .drop_foreign_key(Alias::new("fk-interaction-OrganisationId"))
                    .drop_column(Interaction::OrganisationId)
                    .to_owned(),
            )
            .await
    }
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .drop_table(Table::drop().table(Interaction::Table).to_owned())
        .await?;
    let datetime = CustomDateTime(manager.get_database_backend());

    manager
        .create_table(
            Table::create()
                .table(Interaction::Table)
                .col(
                    ColumnDef::new(Interaction::Id)
                        .char_len(36)
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(Interaction::CreatedDate)
                        .custom(datetime)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(Interaction::LastModified)
                        .custom(datetime)
                        .not_null(),
                )
                .col(ColumnDef::new(Interaction::Host).string())
                .col(ColumnDef::new(Interaction::Data).custom_blob(manager))
                .col(
                    ColumnDef::new(Interaction::OrganisationId)
                        .char_len(36)
                        .not_null(),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-interaction-OrganisationId")
                        .from_tbl(Interaction::Table)
                        .from_col(Interaction::OrganisationId)
                        .to_tbl(Organisation::Table)
                        .to_col(Organisation::Id),
                )
                .to_owned(),
        )
        .await
}

async fn sane_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(Alias::new(TABLE))
                .add_column(
                    ColumnDef::new(Interaction::OrganisationId)
                        .char_len(36)
                        .not_null(),
                )
                .add_foreign_key(
                    ForeignKey::create()
                        .name("fk-interaction-OrganisationId")
                        .from_tbl(Interaction::Table)
                        .from_col(Interaction::OrganisationId)
                        .to_tbl(Organisation::Table)
                        .to_col(Organisation::Id)
                        .get_foreign_key(),
                )
                .to_owned(),
        )
        .await
}

#[derive(Iden)]
pub enum Organisation {
    Table,
    Id,
}

#[derive(Iden)]
pub enum Interaction {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Host,
    Data,
    OrganisationId,
}
