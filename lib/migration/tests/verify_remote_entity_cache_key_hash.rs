#![allow(clippy::unwrap_used)]

use migration::Migrator;
use migration::test_utilities::{drop_database, with_database};
use sea_orm::{
    ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, Statement, TransactionTrait,
};
use sea_orm_migration::MigratorTrait;
use sha2::{Digest, Sha256};

const KEY: &str = "https://example.com/context.jsonld";

#[tokio::test]
async fn test_remote_entity_cache_key_hash_backfill() {
    let (db, server) = connect().await;
    let txn = db.begin().await.unwrap();
    let total = Migrator::migrations()
        .iter()
        .take_while(|m| m.name() != "m20261027_150000_remote_entity_cache_key_hash")
        .count() as u32;
    Migrator::up(&txn, Some(total)).await.unwrap();

    // `key` is a reserved word in MySQL
    let key_column = if db.get_database_backend() == DatabaseBackend::MySql {
        "`key`"
    } else {
        "key"
    };
    txn.execute_unprepared(&format!(
        "INSERT INTO remote_entity_cache (id, created_date, last_modified, last_used, type, {key_column}, value) VALUES \
        ('00000000-0000-0000-0000-000000000010', '2024-01-01 00:00:00', '2024-01-01 00:00:00', '2024-01-01 00:00:00', 'JSON_LD_CONTEXT', '{KEY}', '')"
    ))
    .await
    .unwrap();

    Migrator::up(&txn, Some(1)).await.unwrap();
    txn.commit().await.unwrap();

    let hash: Option<String> = db
        .query_one_raw(Statement::from_string(
            db.get_database_backend(),
            "SELECT key_hash FROM remote_entity_cache WHERE id = '00000000-0000-0000-0000-000000000010'",
        ))
        .await
        .unwrap()
        .map(|row| row.try_get_by_index(0).unwrap());
    if let Some((server, name)) = server {
        db.close().await.unwrap();
        drop_database(&server, &name).await;
    }

    similar_asserts::assert_eq!(hash, Some(hex::encode(Sha256::digest(KEY))));
}

/// A new database on the server of `ONE_app__databaseUrl`, or SQLite in memory.
async fn connect() -> (DatabaseConnection, Option<(DatabaseConnection, String)>) {
    let Ok(url) = std::env::var("ONE_app__databaseUrl") else {
        return (Database::connect("sqlite::memory:").await.unwrap(), None);
    };
    let url = url.parse().unwrap();
    let server = Database::connect(with_database(&url, "")).await.unwrap();
    let name = format!(
        "remote_entity_cache_key_hash_test_{}",
        ulid::Ulid::new().to_string().to_lowercase()
    );
    server
        .execute_unprepared(&format!("CREATE DATABASE {name}"))
        .await
        .unwrap();
    let db = Database::connect(with_database(&url, &name)).await.unwrap();
    (db, Some((server, name)))
}
