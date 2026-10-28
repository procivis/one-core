use sea_orm::{ConnectionTrait, FromQueryResult};
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{string, string_len, string_null};
use sha2::{Digest, Sha256};

use crate::datatype::{large_blob, timestamp, timestamp_null, uuid_char};
use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

#[derive(DeriveMigrationName)]
pub struct Migration;

const INDEX_NAME: &str = "index-RemoteEntityCache-Key-Unique";
const INDEX_TYPE_EXPIRATION_DATE: &str = "index-RemoteEntityCache-Type-ExpirationDate";
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
        .create_table(
            Table::create()
                .table(RemoteEntityCacheNew::Table)
                .col(uuid_char(RemoteEntityCache::Id).primary_key())
                .col(timestamp(RemoteEntityCache::CreatedDate, manager))
                .col(timestamp(RemoteEntityCache::LastModified, manager))
                .col(timestamp(RemoteEntityCache::LastUsed, manager))
                .col(timestamp_null(RemoteEntityCache::ExpirationDate, manager))
                .col(string(RemoteEntityCache::Type))
                .col(string_len(RemoteEntityCache::Key, 4096))
                .col(string_len(RemoteEntityCache::KeyHash, 64))
                .col(string_null(RemoteEntityCache::MediaType))
                .col(large_blob(RemoteEntityCache::Value, manager))
                .to_owned(),
        )
        .await?;

    let copied_columns = vec![
        RemoteEntityCache::Id,
        RemoteEntityCache::CreatedDate,
        RemoteEntityCache::LastModified,
        RemoteEntityCache::LastUsed,
        RemoteEntityCache::ExpirationDate,
        RemoteEntityCache::Type,
        RemoteEntityCache::Key,
        RemoteEntityCache::KeyHash,
        RemoteEntityCache::MediaType,
        RemoteEntityCache::Value,
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(RemoteEntityCacheNew::Table)
                .columns(copied_columns.clone())
                .select_from(
                    Query::select()
                        .columns(copied_columns)
                        .from(RemoteEntityCache::Table)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    manager
        .drop_table(Table::drop().table(RemoteEntityCache::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(RemoteEntityCacheNew::Table, RemoteEntityCache::Table)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name(INDEX_TYPE_EXPIRATION_DATE)
                .table(RemoteEntityCache::Table)
                .col(RemoteEntityCache::Type)
                .col(RemoteEntityCache::ExpirationDate)
                .to_owned(),
        )
        .await
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

#[derive(DeriveIden)]
enum RemoteEntityCacheNew {
    Table,
}
