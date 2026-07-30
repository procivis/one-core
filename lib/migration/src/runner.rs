use sea_orm::{
    ConnectionTrait, DatabaseBackend, DatabaseConnection, DatabaseTransaction, DbErr, Statement,
    TransactionTrait,
};
use sea_orm_migration::prelude::*;

use crate::{LegacyMigrator, Migrator};

const PG_ADVISORY_LOCK_KEY: i64 = i64::from_be_bytes(*b"\0onecore");
// GET_LOCK is server-wide, so include the schema name (max 64 chars total)
const MYSQL_LOCK_NAME_EXPR: &str = "CONCAT('one-core-migration:', IFNULL(DATABASE(), ''))";
const LOCK_TIMEOUT_SECS: u32 = 600;

const LEGACY_MIGRATION_MARKER: &str = "m20240110_000001_initial";

/// Runs pending migrations under an advisory lock so that concurrently
/// starting instances don't apply them twice. The surrounding transaction
/// pins one pooled connection, the lock is tied to that session.
pub async fn run_migrations(db: &DatabaseConnection) -> Result<(), DbErr> {
    let txn = db.begin().await?;
    acquire_migration_lock(&txn).await?;

    let result = async {
        clean_up_legacy_migrations(&txn).await?;
        Migrator::up(&txn, None).await
    }
    .await;

    match result {
        Ok(()) => commit_and_release(txn).await,
        Err(error) => {
            release_mysql_lock(&txn).await;
            if let Err(rollback_error) = txn.rollback().await {
                tracing::warn!(%rollback_error, "failed to roll back migration transaction");
            }
            Err(error)
        }
    }
}

async fn acquire_migration_lock(txn: &DatabaseTransaction) -> Result<(), DbErr> {
    match txn.get_database_backend() {
        DatabaseBackend::Postgres => {
            txn.execute_unprepared(&format!("SET LOCAL lock_timeout = '{LOCK_TIMEOUT_SECS}s'"))
                .await?;
            txn.execute_unprepared(&format!(
                "SELECT pg_advisory_xact_lock({PG_ADVISORY_LOCK_KEY})"
            ))
            .await?;
            Ok(())
        }
        DatabaseBackend::MySql => {
            let acquired: Option<i64> = txn
                .query_one(Statement::from_string(
                    DatabaseBackend::MySql,
                    format!("SELECT GET_LOCK({MYSQL_LOCK_NAME_EXPR}, {LOCK_TIMEOUT_SECS})"),
                ))
                .await?
                .and_then(|row| row.try_get_by_index(0).ok());
            if acquired != Some(1) {
                return Err(DbErr::Custom(format!(
                    "failed to acquire migration lock within {LOCK_TIMEOUT_SECS}s \
                     (GET_LOCK returned {acquired:?})"
                )));
            }
            Ok(())
        }
        DatabaseBackend::Sqlite => Ok(()),
    }
}

async fn commit_and_release(txn: DatabaseTransaction) -> Result<(), DbErr> {
    if txn.get_database_backend() == DatabaseBackend::MySql {
        // commit before releasing the lock, otherwise the next holder may not
        // see all version table entries yet; the final commit() is then a no-op
        txn.execute_unprepared("COMMIT").await?;
        release_mysql_lock(&txn).await;
    }
    txn.commit().await
}

async fn release_mysql_lock(txn: &DatabaseTransaction) {
    if txn.get_database_backend() != DatabaseBackend::MySql {
        return;
    }
    if let Err(error) = txn
        .execute_unprepared(&format!("SELECT RELEASE_LOCK({MYSQL_LOCK_NAME_EXPR})"))
        .await
    {
        tracing::warn!(%error, "failed to release migration lock");
    }
}

async fn clean_up_legacy_migrations(txn: &DatabaseTransaction) -> Result<(), DbErr> {
    LegacyMigrator::install(txn).await?;
    let migration_models = LegacyMigrator::get_migration_models(txn).await?;
    let applied_migrations: Vec<&str> = migration_models
        .iter()
        .map(|m| m.version.as_str())
        .collect();
    if applied_migrations.contains(&LEGACY_MIGRATION_MARKER) {
        LegacyMigrator::up(txn, None).await?;
        let stmt = txn
            .get_database_backend()
            .build(Query::delete().from_table(LegacyMigrator::migration_table_name()));
        txn.execute(stmt).await?;
    }
    Ok(())
}
