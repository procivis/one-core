use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;
use crate::m20240110_000001_initial::{Did, Key, Organisation};
use crate::m20250429_142011_add_identifier::Identifier;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DatabaseBackend::Sqlite {
            sqlite_migration(manager).await
        } else {
            manager
                .alter_table(
                    Table::alter()
                        .table(Identifier::Table)
                        .rename_column(Identifier::Status, IdentifierNew::State)
                        .to_owned(),
                )
                .await
        }
    }
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .get_connection()
        .execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    manager
        .create_table(
            Table::create()
                .table(IdentifierNew::Table)
                .col(
                    ColumnDef::new(IdentifierNew::Id)
                        .char_len(36)
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(IdentifierNew::CreatedDate)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(IdentifierNew::LastModified)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(ColumnDef::new(IdentifierNew::Name).string().not_null())
                .col(ColumnDef::new(IdentifierNew::Type).string().not_null())
                .col(ColumnDef::new(IdentifierNew::IsRemote).boolean().not_null())
                .col(ColumnDef::new(IdentifierNew::State).string().not_null())
                .col(ColumnDef::new(IdentifierNew::OrganisationId).char_len(36))
                .col(ColumnDef::new(IdentifierNew::DidId).char_len(36))
                .col(ColumnDef::new(IdentifierNew::KeyId).char_len(36))
                .col(
                    ColumnDef::new(IdentifierNew::DeletedAt)
                        .datetime_millisecond_precision(manager)
                        .null(),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_identifier_organisation")
                        .from(IdentifierNew::Table, IdentifierNew::OrganisationId)
                        .to(Organisation::Table, Organisation::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_identifier_did")
                        .from(IdentifierNew::Table, IdentifierNew::DidId)
                        .to(Did::Table, Did::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_identifier_key")
                        .from(IdentifierNew::Table, IdentifierNew::KeyId)
                        .to(Key::Table, Key::Id),
                )
                .to_owned(),
        )
        .await?;

    let sql = r#"
        INSERT INTO identifier_new
        SELECT id, created_date, last_modified, name, type, is_remote, status, organisation_id, did_id, key_id, deleted_at
        FROM identifier;
    "#;
    manager.get_connection().execute_unprepared(sql).await?;

    manager
        .drop_table(Table::drop().table(Identifier::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(IdentifierNew::Table, Identifier::Table)
                .to_owned(),
        )
        .await?;

    manager
        .get_connection()
        .execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}

#[derive(DeriveIden)]
pub enum IdentifierNew {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Name,
    Type,
    IsRemote,
    State,
    OrganisationId,
    DidId,
    KeyId,
    DeletedAt,
}
