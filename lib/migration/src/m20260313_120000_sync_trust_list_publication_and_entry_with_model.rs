use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

use crate::datatype::{ColumnDefExt, timestamp, timestamp_null, uuid_char, uuid_char_null};
use crate::m20240110_000001_initial::{Key, Organisation};
use crate::m20250429_142011_add_identifier::Identifier;
use crate::m20250512_110852_certificate::Certificate;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DatabaseBackend::Postgres => {}
            DatabaseBackend::MySql => mysql_migration(manager).await?,
            DatabaseBackend::Sqlite => sqlite_migration(manager).await?,
        };

        Ok(())
    }
}

#[derive(Clone, Iden)]
enum TrustEntry {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Status,
    Metadata,
    TrustListPublicationId,
    IdentifierId,
}

#[derive(Clone, Iden)]
enum TrustListPublication {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Name,
    Role,
    Type,
    Metadata,
    DeactivatedAt,
    Content,
    SequenceNumber,
    OrganisationId,
    IdentifierId,
    KeyId,
    CertificateId,
}

async fn mysql_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    // trust_list_publication fixes:
    // - content: NOT NULL (was nullable)
    // - identifier_id: NOT NULL (was nullable)
    // - sequence_number: unsigned (was big_integer)

    // Drop FK before modifying identifier_id (MySQL cannot alter FK-referenced columns)
    manager
        .alter_table(
            Table::alter()
                .table(TrustListPublication::Table)
                .drop_foreign_key(Alias::new("fk-TrustListPublication-IdentifierId"))
                .to_owned(),
        )
        .await?;

    manager
        .alter_table(
            Table::alter()
                .table(TrustListPublication::Table)
                .modify_column(
                    ColumnDef::new(TrustListPublication::Content)
                        .large_blob(manager)
                        .not_null(),
                )
                .modify_column(uuid_char(TrustListPublication::IdentifierId).not_null())
                .modify_column(unsigned(TrustListPublication::SequenceNumber))
                .to_owned(),
        )
        .await?;

    // Re-add FK
    manager
        .alter_table(
            Table::alter()
                .table(TrustListPublication::Table)
                .add_foreign_key(
                    ForeignKey::create()
                        .name("fk-TrustListPublication-IdentifierId")
                        .from_tbl(TrustListPublication::Table)
                        .from_col(TrustListPublication::IdentifierId)
                        .to_tbl(Identifier::Table)
                        .to_col(Identifier::Id)
                        .on_delete(ForeignKeyAction::Restrict)
                        .get_foreign_key(),
                )
                .to_owned(),
        )
        .await?;

    // trust_entry fixes:
    // - identifier_id: NOT NULL (was nullable)

    // Drop FK before modifying identifier_id
    manager
        .alter_table(
            Table::alter()
                .table(TrustEntry::Table)
                .drop_foreign_key(Alias::new("fk-TrustEntry-IdentifierId"))
                .to_owned(),
        )
        .await?;

    manager
        .alter_table(
            Table::alter()
                .table(TrustEntry::Table)
                .modify_column(uuid_char(TrustEntry::IdentifierId).not_null())
                .to_owned(),
        )
        .await?;

    // Re-add FK
    manager
        .alter_table(
            Table::alter()
                .table(TrustEntry::Table)
                .add_foreign_key(
                    ForeignKey::create()
                        .name("fk-TrustEntry-IdentifierId")
                        .from_tbl(TrustEntry::Table)
                        .from_col(TrustEntry::IdentifierId)
                        .to_tbl(Identifier::Table)
                        .to_col(Identifier::Id)
                        .on_delete(ForeignKeyAction::Restrict)
                        .get_foreign_key(),
                )
                .to_owned(),
        )
        .await?;

    Ok(())
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();

    db.execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    // Drop existing tables, these are not populated / used on the wallet so no data should be lost
    manager
        .drop_table(Table::drop().table(TrustEntry::Table).to_owned())
        .await?;

    // - role: NOT NULL (was nullable)
    // - content: NOT NULL (was nullable)
    // - sequence_number: unsigned (was big_unsigned)
    // - organisation_id: NOT NULL (was nullable)
    // - identifier_id: NOT NULL (was nullable)
    manager
        .drop_table(Table::drop().table(TrustListPublication::Table).to_owned())
        .await?;

    manager
        .create_table(
            Table::create()
                .table(TrustListPublication::Table)
                .col(uuid_char(TrustListPublication::Id).primary_key())
                .col(timestamp(TrustListPublication::CreatedDate, manager))
                .col(timestamp(TrustListPublication::LastModified, manager))
                .col(text(TrustListPublication::Name))
                .col(string(TrustListPublication::Role))
                .col(string(TrustListPublication::Type))
                .col(
                    ColumnDef::new(TrustListPublication::Metadata)
                        .large_blob(manager)
                        .not_null(),
                )
                .col(timestamp_null(TrustListPublication::DeactivatedAt, manager))
                .col(
                    ColumnDef::new(TrustListPublication::Content)
                        .large_blob(manager)
                        .not_null(),
                )
                .col(unsigned(TrustListPublication::SequenceNumber))
                .col(uuid_char(TrustListPublication::OrganisationId))
                .col(uuid_char(TrustListPublication::IdentifierId))
                .col(uuid_char_null(TrustListPublication::KeyId))
                .col(uuid_char_null(TrustListPublication::CertificateId))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-TrustListPublication-OrganisationId")
                        .from_tbl(TrustListPublication::Table)
                        .from_col(TrustListPublication::OrganisationId)
                        .to_tbl(Organisation::Table)
                        .to_col(Organisation::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-TrustListPublication-IdentifierId")
                        .from_tbl(TrustListPublication::Table)
                        .from_col(TrustListPublication::IdentifierId)
                        .to_tbl(Identifier::Table)
                        .to_col(Identifier::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-TrustListPublication-KeyId")
                        .from_tbl(TrustListPublication::Table)
                        .from_col(TrustListPublication::KeyId)
                        .to_tbl(Key::Table)
                        .to_col(Key::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-TrustListPublication-CertificateId")
                        .from_tbl(TrustListPublication::Table)
                        .from_col(TrustListPublication::CertificateId)
                        .to_tbl(Certificate::Table)
                        .to_col(Certificate::Id),
                )
                .to_owned(),
        )
        .await?;

    // Recreate trust_entry with corrected schema:
    // - identifier_id: NOT NULL (was nullable)
    manager
        .create_table(
            Table::create()
                .table(TrustEntry::Table)
                .col(uuid_char(TrustEntry::Id).primary_key())
                .col(timestamp(TrustEntry::CreatedDate, manager))
                .col(timestamp(TrustEntry::LastModified, manager))
                .col(string(TrustEntry::Status))
                .col(
                    ColumnDef::new(TrustEntry::Metadata)
                        .large_blob(manager)
                        .not_null(),
                )
                .col(uuid_char(TrustEntry::TrustListPublicationId))
                .col(uuid_char(TrustEntry::IdentifierId))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-TrustEntry-TrustListPublicationId")
                        .from_tbl(TrustEntry::Table)
                        .from_col(TrustEntry::TrustListPublicationId)
                        .to_tbl(TrustListPublication::Table)
                        .to_col(TrustListPublication::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-TrustEntry-IdentifierId")
                        .from_tbl(TrustEntry::Table)
                        .from_col(TrustEntry::IdentifierId)
                        .to_tbl(Identifier::Table)
                        .to_col(Identifier::Id),
                )
                .to_owned(),
        )
        .await?;

    db.execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}
