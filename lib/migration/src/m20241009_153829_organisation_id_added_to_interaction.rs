use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

const TABLE: &str = "interaction";
const CREDENTIAL_TABLE: &str = "credential";
const PROOF_TABLE: &str = "proof";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Postgres {
            // Skip because it is not supported. If support for Postgres is added in the future
            // the schema can be setup in its entirety in a new, later migration.
            return Ok(());
        }
        manager
            .get_connection()
            .execute_unprepared(&format!(
                "UPDATE {CREDENTIAL_TABLE} SET interaction_id=null"
            ))
            .await?;
        manager
            .get_connection()
            .execute_unprepared(&format!("UPDATE {PROOF_TABLE} SET interaction_id=null"))
            .await?;
        manager
            .get_connection()
            .execute_unprepared(&format!("DELETE FROM {TABLE}"))
            .await?;

        match manager.get_database_backend() {
            DbBackend::MySql | DbBackend::Postgres => sane_migration(manager).await,
            DbBackend::Sqlite => sqlite_migration(manager).await,
        }
    }
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .drop_table(Table::drop().table(Interaction::Table).to_owned())
        .await?;

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
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(Interaction::LastModified)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(ColumnDef::new(Interaction::Host).string())
                .col(ColumnDef::new(Interaction::Data).large_blob(manager))
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
