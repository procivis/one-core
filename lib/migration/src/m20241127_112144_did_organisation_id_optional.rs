use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;
use crate::m20240110_000001_initial::{Did, DidType, Organisation};
use crate::m20240115_093859_unique_did_name_and_key_name_in_org::UNIQUE_DID_NAME_IN_ORGANISATION_INDEX;
use crate::m20240116_110014_unique_did_in_organisation::UNIQUE_DID_DID_IN_ORGANISATION_INDEX;
use crate::m20240209_144950_add_verifier_key_id_to_proof::copy_data_to_new_tables;

#[derive(DeriveMigrationName)]
pub struct Migration;

const DID_ORGANISATION_FOREIGN_KEY_NAME: &str = "fk-Did-OrganisationId";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DbBackend::Postgres => Ok(()),
            DbBackend::Sqlite => sqlite_migration(manager).await,
            _ => sane_migration(manager).await,
        }
    }
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(DidNew::Table)
                .col(
                    ColumnDef::new(DidNew::Id)
                        .char_len(36)
                        .not_null()
                        .primary_key(),
                )
                .col(ColumnDef::new(DidNew::Did).string_len(4000).not_null())
                .col(
                    ColumnDef::new(DidNew::CreatedDate)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(DidNew::LastModified)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(ColumnDef::new(DidNew::Name).string().not_null())
                .col(
                    ColumnDef::new(DidNew::Type)
                        .enumeration(DidType::Table, [DidType::Remote, DidType::Local])
                        .not_null(),
                )
                .col(ColumnDef::new(DidNew::Method).string().not_null())
                .col(ColumnDef::new(DidNew::OrganisationId).char_len(36))
                .col(ColumnDef::new(DidNew::Deactivated).boolean().not_null())
                .col(ColumnDef::new(DidNew::DeletedAt).datetime_millisecond_precision(manager))
                .foreign_key(
                    ForeignKey::create()
                        .name(DID_ORGANISATION_FOREIGN_KEY_NAME)
                        .from_tbl(DidNew::Table)
                        .from_col(Did::OrganisationId)
                        .to_tbl(Organisation::Table)
                        .to_col(Organisation::Id),
                )
                .to_owned(),
        )
        .await?;

    manager
        .drop_index(
            Index::drop()
                .name(UNIQUE_DID_DID_IN_ORGANISATION_INDEX)
                .table(Did::Table)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name(UNIQUE_DID_DID_IN_ORGANISATION_INDEX)
                .unique()
                .table(DidNew::Table)
                .col(Did::Did)
                .col(Did::OrganisationId)
                .to_owned(),
        )
        .await?;

    manager
        .drop_index(
            Index::drop()
                .name(UNIQUE_DID_NAME_IN_ORGANISATION_INDEX)
                .table(Did::Table)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name(UNIQUE_DID_NAME_IN_ORGANISATION_INDEX)
                .table(DidNew::Table)
                .col(Did::Name)
                .col(Did::OrganisationId)
                .unique()
                .to_owned(),
        )
        .await?;

    let connection = manager.get_connection();

    copy_data_to_new_tables(connection, vec![("did", "did_new")]).await?;

    manager
        .get_connection()
        .execute_unprepared("PRAGMA defer_foreign_keys = ON; DROP TABLE `did`; ALTER TABLE `did_new` RENAME TO `did`; PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}

async fn sane_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(Did::Table)
                .modify_column(ColumnDef::new(Did::OrganisationId).char_len(36))
                .to_owned(),
        )
        .await
}

#[derive(DeriveIden)]
pub enum DidNew {
    Table,
    Id,
    Did,
    CreatedDate,
    LastModified,
    DeletedAt,
    Name,
    Type,
    Method,
    OrganisationId,
    Deactivated,
}
