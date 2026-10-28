use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{integer, string};

use crate::datatype::{large_blob, timestamp, timestamp_null, uuid_char, uuid_char_null};
use crate::migrations::m20260417_150300_initial::{Certificate, Identifier, Key, Organisation};
use crate::nullable_unique_idx::{NullableIdxOpts, add_nullable_unique_idx};
use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

#[derive(DeriveMigrationName)]
pub struct Migration;

const INDEX_NAME: &str = "index-TrustPublication-Name-Org-DeactivatedAt-Unique";

/// Shrinks the publication name from TEXT to VARCHAR(255), the size of the other name columns.
///
/// A TEXT column is longer than an index key. MariaDB then builds a `USING HASH` unique index,
/// and its duplicate check deadlocks concurrent inserts.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let drop_index = match manager.supported_db_type() {
            SupportedDbType::MySql => {
                format!("ALTER TABLE trust_list_publication DROP INDEX IF EXISTS `{INDEX_NAME}`")
            }
            _ => format!("DROP INDEX IF EXISTS \"{INDEX_NAME}\""),
        };
        manager
            .get_connection()
            .execute_unprepared(&drop_index)
            .await?;

        if manager.supported_db_type() == SupportedDbType::Sqlite {
            up_sqlite(manager).await?;
        } else {
            manager
                .alter_table(
                    Table::alter()
                        .table(TrustListPublication::Table)
                        .modify_column(string(TrustListPublication::Name))
                        .to_owned(),
                )
                .await?;
        }

        add_nullable_unique_idx(
            TrustListPublication::Table,
            TrustListPublication::DeactivatedAt,
            INDEX_NAME,
            NullableIdxOpts {
                non_nullable_columns: vec![
                    TrustListPublication::Name,
                    TrustListPublication::OrganisationId,
                ],
                null_value: Some("not_deactivated"),
                ..Default::default()
            },
            manager,
        )
        .await
    }
}

async fn up_sqlite(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();
    db.execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    manager
        .create_table(
            Table::create()
                .table(TrustListPublicationNew::Table)
                .col(uuid_char(TrustListPublication::Id).primary_key())
                .col(timestamp(TrustListPublication::CreatedDate, manager))
                .col(timestamp(TrustListPublication::LastModified, manager))
                .col(timestamp_null(TrustListPublication::DeactivatedAt, manager))
                .col(string(TrustListPublication::Role))
                .col(string(TrustListPublication::Type))
                .col(string(TrustListPublication::Name))
                .col(large_blob(TrustListPublication::Metadata, manager))
                .col(large_blob(TrustListPublication::Content, manager))
                .col(integer(TrustListPublication::SequenceNumber))
                .col(uuid_char(TrustListPublication::OrganisationId))
                .col(uuid_char(TrustListPublication::IdentifierId))
                .col(uuid_char_null(TrustListPublication::CertificateId))
                .col(uuid_char_null(TrustListPublication::KeyId))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk-TrustListPublication-OrganisationId")
                        .from_tbl(TrustListPublicationNew::Table)
                        .from_col(TrustListPublication::OrganisationId)
                        .to_tbl(Organisation::Table)
                        .to_col(Organisation::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk-TrustListPublication-IdentifierId")
                        .from_tbl(TrustListPublicationNew::Table)
                        .from_col(TrustListPublication::IdentifierId)
                        .to_tbl(Identifier::Table)
                        .to_col(Identifier::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk-TrustListPublication-CertificateId")
                        .from_tbl(TrustListPublicationNew::Table)
                        .from_col(TrustListPublication::CertificateId)
                        .to_tbl(Certificate::Table)
                        .to_col(Certificate::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk-TrustListPublication-KeyId")
                        .from_tbl(TrustListPublicationNew::Table)
                        .from_col(TrustListPublication::KeyId)
                        .to_tbl(Key::Table)
                        .to_col(Key::Id),
                )
                .to_owned(),
        )
        .await?;

    let copied_columns = vec![
        TrustListPublication::Id,
        TrustListPublication::CreatedDate,
        TrustListPublication::LastModified,
        TrustListPublication::DeactivatedAt,
        TrustListPublication::Role,
        TrustListPublication::Type,
        TrustListPublication::Name,
        TrustListPublication::Metadata,
        TrustListPublication::Content,
        TrustListPublication::SequenceNumber,
        TrustListPublication::OrganisationId,
        TrustListPublication::IdentifierId,
        TrustListPublication::CertificateId,
        TrustListPublication::KeyId,
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(TrustListPublicationNew::Table)
                .columns(copied_columns.clone())
                .select_from(
                    Query::select()
                        .columns(copied_columns)
                        .from(TrustListPublication::Table)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    manager
        .drop_table(Table::drop().table(TrustListPublication::Table).to_owned())
        .await?;
    manager
        .rename_table(
            Table::rename()
                .table(TrustListPublicationNew::Table, TrustListPublication::Table)
                .to_owned(),
        )
        .await?;

    db.execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await
        .map(|_| ())
}

#[derive(Clone, DeriveIden)]
enum TrustListPublication {
    Table,
    Id,
    CreatedDate,
    LastModified,
    DeactivatedAt,
    Name,
    Role,
    Type,
    Metadata,
    Content,
    SequenceNumber,
    OrganisationId,
    IdentifierId,
    CertificateId,
    KeyId,
}

#[derive(DeriveIden)]
enum TrustListPublicationNew {
    Table,
}
