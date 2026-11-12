use sea_orm::{ConnectionTrait, FromQueryResult};
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{string, string_len, string_null};
use sea_orm_migration_sqlite::{SchemaManagerExt, TableExt};
use sha2::{Digest, Sha256};

use crate::datatype::{large_blob, timestamp, timestamp_null, uuid_char};
use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

#[derive(DeriveMigrationName)]
pub struct Migration;

const INDEX_NAME: &str = "index-RemoteEntityCache-Key-Unique";
const PAGE_SIZE: u64 = 1000;

/// Moves the unique index of the cache key from the key itself to its SHA-256.
///
/// A key can be longer than an index key. MariaDB then builds a `USING HASH` unique index, and
/// its duplicate check deadlocks concurrent inserts.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let db_type = manager.supported_db_type();
        manager
            .alter_table(
                Table::alter()
                    .table(RemoteEntityCache::Table)
                    .add_column_if_not_exists(
                        string_len(RemoteEntityCache::KeyHash, 64).default(""),
                    )
                    .to_owned(),
            )
            .await?;
        let drop_index = match db_type {
            SupportedDbType::MySql => {
                format!("ALTER TABLE remote_entity_cache DROP INDEX IF EXISTS `{INDEX_NAME}`")
            }
            _ => format!("DROP INDEX IF EXISTS \"{INDEX_NAME}\""),
        };
        db.execute_unprepared(&drop_index).await?;

        if db_type == SupportedDbType::Sqlite {
            up_sqlite(manager).await?;
        } else {
            db.execute_unprepared(&format!(
                "ALTER TABLE {table} ALTER COLUMN {column} DROP DEFAULT",
                table = RemoteEntityCache::Table.to_string(),
                column = RemoteEntityCache::KeyHash.to_string(),
            ))
            .await?;
        }

        match db_type {
            SupportedDbType::MySql => {
                db.execute_unprepared(
                    "UPDATE remote_entity_cache SET key_hash = SHA2(CONVERT(`key` USING utf8mb4), 256) WHERE key_hash = ''",
                )
                .await?;
            }
            SupportedDbType::Postgres => {
                db.execute_unprepared(
                    "UPDATE remote_entity_cache SET key_hash = encode(sha256(convert_to(key, 'UTF8')), 'hex') WHERE key_hash = ''",
                )
                .await?;
            }
            SupportedDbType::Sqlite => backfill_rows(db).await?,
        }

        manager
            .create_index(
                Index::create()
                    .name(INDEX_NAME)
                    .unique()
                    .table(RemoteEntityCache::Table)
                    .col(RemoteEntityCache::KeyHash)
                    .to_owned(),
            )
            .await
    }
}

fn key_hash(key: &str) -> String {
    hex::encode(Sha256::digest(key))
}

#[derive(FromQueryResult)]
struct Row {
    id: String,
    key: String,
}

async fn backfill_rows(db: &impl ConnectionTrait) -> Result<(), DbErr> {
    let mut cursor: Option<String> = None;
    loop {
        let mut query = Query::select();
        query
            .columns([RemoteEntityCache::Id, RemoteEntityCache::Key])
            .from(RemoteEntityCache::Table)
            .order_by(RemoteEntityCache::Id, Order::Asc)
            .limit(PAGE_SIZE);
        if let Some(id) = &cursor {
            query.and_where(Expr::col(RemoteEntityCache::Id).gt(id));
        }
        let rows = Row::find_by_statement(db.get_database_backend().build(&query))
            .all(db)
            .await?;
        let Some(last) = rows.last() else {
            return Ok(());
        };
        cursor = Some(last.id.clone());
        for row in &rows {
            db.execute(
                Query::update()
                    .table(RemoteEntityCache::Table)
                    .value(RemoteEntityCache::KeyHash, key_hash(&row.key))
                    .and_where(Expr::col(RemoteEntityCache::Id).eq(&row.id)),
            )
            .await?;
        }
    }
}

async fn up_sqlite(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .recreate_table(
            Table::recreate()
                .table(RemoteEntityCache::Table)
                .modify_column(uuid_char(RemoteEntityCache::Id).primary_key())
                .modify_column(timestamp(RemoteEntityCache::CreatedDate, manager))
                .modify_column(timestamp(RemoteEntityCache::LastModified, manager))
                .modify_column(timestamp(RemoteEntityCache::LastUsed, manager))
                .modify_column(timestamp_null(RemoteEntityCache::ExpirationDate, manager))
                .modify_column(string(RemoteEntityCache::Type))
                .modify_column(string_len(RemoteEntityCache::Key, 4096))
                .modify_column(string_len(RemoteEntityCache::KeyHash, 64))
                .modify_column(string_null(RemoteEntityCache::MediaType))
                .modify_column(large_blob(RemoteEntityCache::Value, manager))
                .to_owned(),
        )
        .await?;

    Ok(())
}

#[derive(Clone, DeriveIden)]
enum RemoteEntityCache {
    Table,
    Id,
    CreatedDate,
    LastModified,
    LastUsed,
    ExpirationDate,
    Type,
    Key,
    KeyHash,
    MediaType,
    Value,
}
