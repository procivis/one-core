#![allow(clippy::unwrap_used)]

use migration::Migrator;
use migration::test_utilities::{drop_database, with_database};
use sea_orm::{ConnectionTrait, Database, DatabaseConnection, Statement, TransactionTrait};
use sea_orm_migration::MigratorTrait;
use sha2::{Digest, Sha256};

const DID: &str = "did:example:123";

#[tokio::test]
async fn test_did_hash_backfill() {
    let (db, server) = connect().await;
    let txn = db.begin().await.unwrap();
    let total = Migrator::migrations()
        .iter()
        .take_while(|m| m.name() != "m20261027_130000_did_hash")
        .count() as u32;
    Migrator::up(&txn, Some(total)).await.unwrap();

    txn.execute_unprepared(
        "INSERT INTO organisation (id, created_date, last_modified) VALUES ('00000000-0000-0000-0000-000000000001', '2024-01-01 00:00:00', '2024-01-01 00:00:00')",
    )
    .await
    .unwrap();
    // the same DID active and deleted
    txn.execute_unprepared(&format!(
        "INSERT INTO did (id, created_date, last_modified, deleted_at, did, name, type, method, deactivated, organisation_id) VALUES \
        ('00000000-0000-0000-0000-000000000010', '2024-01-01 00:00:00', '2024-01-01 00:00:00', NULL, '{DID}', 'active', 'REMOTE', 'KEY', false, '00000000-0000-0000-0000-000000000001'), \
        ('00000000-0000-0000-0000-000000000011', '2024-01-01 00:00:00', '2024-01-01 00:00:00', '2024-01-01 00:00:00', '{DID}', 'deleted', 'REMOTE', 'KEY', false, '00000000-0000-0000-0000-000000000001')"
    ))
    .await
    .unwrap();

    Migrator::up(&txn, Some(1)).await.unwrap();
    txn.commit().await.unwrap();

    let hashes: Vec<String> = db
        .query_all_raw(Statement::from_string(
            db.get_database_backend(),
            "SELECT did_hash FROM did",
        ))
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.try_get_by_index(0).unwrap())
        .collect();
    if let Some((server, name)) = server {
        db.close().await.unwrap();
        drop_database(&server, &name).await;
    }

    similar_asserts::assert_eq!(hashes, vec![hex::encode(Sha256::digest(DID)); 2]);
}

/// A new database on the server of `ONE_app__databaseUrl`, or SQLite in memory.
async fn connect() -> (DatabaseConnection, Option<(DatabaseConnection, String)>) {
    let Ok(url) = std::env::var("ONE_app__databaseUrl") else {
        return (Database::connect("sqlite::memory:").await.unwrap(), None);
    };
    let url = url.parse().unwrap();
    let server = Database::connect(with_database(&url, "")).await.unwrap();
    let name = format!(
        "did_hash_test_{}",
        ulid::Ulid::new().to_string().to_lowercase()
    );
    server
        .execute_unprepared(&format!("CREATE DATABASE {name}"))
        .await
        .unwrap();
    let db = Database::connect(with_database(&url, &name)).await.unwrap();
    (db, Some((server, name)))
}
