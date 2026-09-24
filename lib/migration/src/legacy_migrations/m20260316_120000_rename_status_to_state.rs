use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

use crate::datatype::{ColumnDefExt, timestamp, uuid_char, uuid_char_null};
use crate::m20240110_000001_initial::{Credential, RevocationList};
use crate::m20250429_142011_add_identifier::Identifier;
use crate::m20260302_170000_trust_list_publication::TrustListPublication;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DbBackend::Postgres => Ok(()),
            DbBackend::MySql => mysql_migration(manager).await,
            DbBackend::Sqlite => sqlite_migration(manager).await,
            other => {
                return Err(DbErr::BackendNotSupported {
                    db: other.as_str(),
                    ctx: "migration",
                });
            }
        }
    }
}

async fn mysql_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(TrustEntry::Table)
                .rename_column(TrustEntry::Status, TrustEntryNew::State)
                .to_owned(),
        )
        .await?;

    manager
        .alter_table(
            Table::alter()
                .table(RevocationListEntry::Table)
                .rename_column(RevocationListEntry::Status, RevocationListEntryNew::State)
                .to_owned(),
        )
        .await?;

    Ok(())
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();

    db.execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    manager
        .create_table(
            Table::create()
                .table(TrustEntryNew::Table)
                .col(uuid_char(TrustEntryNew::Id).primary_key())
                .col(timestamp(TrustEntryNew::CreatedDate, manager))
                .col(timestamp(TrustEntryNew::LastModified, manager))
                .col(string(TrustEntryNew::State))
                .col(
                    ColumnDef::new(TrustEntryNew::Metadata)
                        .large_blob(manager)
                        .not_null(),
                )
                .col(uuid_char(TrustEntryNew::TrustListPublicationId))
                .col(uuid_char(TrustEntryNew::IdentifierId))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-TrustEntry-TrustListPublicationId")
                        .from_tbl(TrustEntryNew::Table)
                        .from_col(TrustEntryNew::TrustListPublicationId)
                        .to_tbl(TrustListPublication::Table)
                        .to_col(TrustListPublication::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-TrustEntry-IdentifierId")
                        .from_tbl(TrustEntryNew::Table)
                        .from_col(TrustEntryNew::IdentifierId)
                        .to_tbl(Identifier::Table)
                        .to_col(Identifier::Id),
                )
                .to_owned(),
        )
        .await?;

    let sql = r#"
        INSERT INTO trust_entry_new
        SELECT id, created_date, last_modified, status, metadata, trust_list_publication_id, identifier_id
        FROM trust_entry;
    "#;
    db.execute_unprepared(sql).await?;

    manager
        .drop_table(Table::drop().table(TrustEntry::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(TrustEntryNew::Table, TrustEntry::Table)
                .to_owned(),
        )
        .await?;

    manager
        .create_table(
            Table::create()
                .table(RevocationListEntryNew::Table)
                .col(uuid_char(RevocationListEntryNew::Id).primary_key())
                .col(timestamp(RevocationListEntryNew::CreatedDate, manager))
                .col(timestamp(RevocationListEntryNew::LastModified, manager))
                .col(uuid_char(RevocationListEntryNew::RevocationListId))
                .col(unsigned_null(RevocationListEntryNew::Index))
                .col(uuid_char_null(RevocationListEntryNew::CredentialId))
                .col(string(RevocationListEntryNew::Type))
                .col(string_null(RevocationListEntryNew::SignatureType))
                .col(string(RevocationListEntryNew::State))
                .col(var_binary_null(RevocationListEntryNew::Serial, 20))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk-RevocationListEntry-RevocationListId")
                        .from_tbl(RevocationListEntryNew::Table)
                        .from_col(RevocationListEntryNew::RevocationListId)
                        .to_tbl(RevocationList::Table)
                        .to_col(RevocationList::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk-RevocationListEntry-CredentialId")
                        .from_tbl(RevocationListEntryNew::Table)
                        .from_col(RevocationListEntryNew::CredentialId)
                        .to_tbl(Credential::Table)
                        .to_col(Credential::Id),
                )
                .to_owned(),
        )
        .await?;

    let sql = r#"
        INSERT INTO revocation_list_entry_new
        SELECT id, created_date, last_modified, revocation_list_id, "index", credential_id, type, signature_type, status, serial
        FROM revocation_list_entry;
    "#;
    db.execute_unprepared(sql).await?;

    manager
        .drop_table(Table::drop().table(RevocationListEntry::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(RevocationListEntryNew::Table, RevocationListEntry::Table)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-RevocationList-Index-Unique")
                .unique()
                .table(RevocationListEntry::Table)
                .col(RevocationListEntryNew::RevocationListId)
                .col(RevocationListEntryNew::Index)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-RevocationList-Serial-Unique")
                .unique()
                .table(RevocationListEntry::Table)
                .col(RevocationListEntryNew::RevocationListId)
                .col(RevocationListEntryNew::Serial)
                .to_owned(),
        )
        .await?;

    db.execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}

#[derive(DeriveIden)]
enum TrustEntry {
    Table,
    #[sea_orm(iden = "status")]
    Status,
}

#[derive(DeriveIden)]
enum TrustEntryNew {
    #[sea_orm(iden = "trust_entry_new")]
    Table,
    Id,
    CreatedDate,
    LastModified,
    State,
    Metadata,
    TrustListPublicationId,
    IdentifierId,
}

#[derive(DeriveIden)]
enum RevocationListEntry {
    Table,
    #[sea_orm(iden = "status")]
    Status,
}

#[derive(DeriveIden)]
enum RevocationListEntryNew {
    #[sea_orm(iden = "revocation_list_entry_new")]
    Table,
    Id,
    CreatedDate,
    LastModified,
    RevocationListId,
    Index,
    CredentialId,
    Type,
    SignatureType,
    State,
    Serial,
}
