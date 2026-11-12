use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{integer, string};
use sea_orm_migration_sqlite::{SchemaManagerExt, TableExt};

use crate::datatype::{large_blob, timestamp, timestamp_null, uuid_char, uuid_char_null};
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
        .recreate_table(
            Table::recreate()
                .table(TrustListPublication::Table)
                .modify_column(uuid_char(TrustListPublication::Id).primary_key())
                .modify_column(timestamp(TrustListPublication::CreatedDate, manager))
                .modify_column(timestamp(TrustListPublication::LastModified, manager))
                .modify_column(timestamp_null(TrustListPublication::DeactivatedAt, manager))
                .modify_column(string(TrustListPublication::Role))
                .modify_column(string(TrustListPublication::Type))
                .modify_column(string(TrustListPublication::Name))
                .modify_column(large_blob(TrustListPublication::Metadata, manager))
                .modify_column(large_blob(TrustListPublication::Content, manager))
                .modify_column(integer(TrustListPublication::SequenceNumber))
                .modify_column(uuid_char(TrustListPublication::OrganisationId))
                .modify_column(uuid_char(TrustListPublication::IdentifierId))
                .modify_column(uuid_char_null(TrustListPublication::CertificateId))
                .modify_column(uuid_char_null(TrustListPublication::KeyId))
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
