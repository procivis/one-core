//! `INIT_DB`: the migrated database on a MariaDB or Postgres server that the
//! core-server integration tests copy and the migration schema tests read.
//! A database is ready when its comment is the migration fingerprint, which is
//! set last.
#![expect(clippy::unwrap_used)]

use std::time::Duration;

use sea_orm::{ConnectOptions, ConnectionTrait, DatabaseConnection, DbBackend, Statement};
use url::Url;

use crate::migration_fingerprint;
use crate::runner::run_migrations;

pub const INIT_DB: &str = "INIT_DB";
/// Postgres: the copy of `INIT_DB` the schema tests read. Their open connections
/// would make `CREATE DATABASE ... TEMPLATE "INIT_DB"` fail.
pub const INIT_DB_SCHEMA: &str = "INIT_DB_SCHEMA";
/// Postgres: the schema with a copy of the rows the migrations insert.
pub const SEED_SCHEMA: &str = "test_seed";
pub const MIGRATION_TABLE: &str = "seaql_migrations";

const MARIADB_LOCK: &str = "one_core_tests_init_db";
const POSTGRES_LOCK: i64 = 9_104_817_237_610_245;

/// Builds `INIT_DB` on the server of `url` unless it is ready. The server lock
/// makes one test process run the migrations while the others wait.
pub async fn prepare_init_db(url: &Url) {
    // The lock belongs to the session: one connection, closed at the end.
    let mut options = ConnectOptions::new(with_database(url, ""));
    options.max_connections(1);
    let server = sea_orm::Database::connect(options).await.unwrap();
    if !all_ready(&server).await {
        lock(&server).await;
        if !all_ready(&server).await {
            build(&server, url).await;
        }
    }
    server.close().await.unwrap();
}

async fn all_ready(server: &DatabaseConnection) -> bool {
    is_ready(server, INIT_DB).await
        && (server.get_database_backend() != DbBackend::Postgres
            || is_ready(server, INIT_DB_SCHEMA).await)
}

pub async fn is_ready(server: &DatabaseConnection, database: &str) -> bool {
    let fingerprint = migration_fingerprint();
    let backend = server.get_database_backend();
    let sql = match backend {
        DbBackend::MySql => format!(
            "SELECT 1 FROM information_schema.schemata \
             WHERE schema_name = '{database}' AND schema_comment = '{fingerprint}';"
        ),
        // The catalog of the server: a connection to `INIT_DB` blocks copies of it.
        _ => format!(
            "SELECT 1 FROM pg_database \
             WHERE datname = '{database}' AND shobj_description(oid, 'pg_database') = '{fingerprint}';"
        ),
    };
    server
        .query_one_raw(Statement::from_string(backend, sql))
        .await
        .unwrap()
        .is_some()
}

pub async fn mark_ready(server: &DatabaseConnection, database: &str) {
    let fingerprint = migration_fingerprint();
    let sql = match server.get_database_backend() {
        DbBackend::MySql => format!("ALTER DATABASE `{database}` COMMENT = '{fingerprint}';"),
        _ => format!("COMMENT ON DATABASE \"{database}\" IS '{fingerprint}';"),
    };
    server.execute_unprepared(&sql).await.unwrap();
}

pub async fn drop_database(server: &DatabaseConnection, database: &str) {
    let sql = match server.get_database_backend() {
        DbBackend::MySql => format!("DROP DATABASE IF EXISTS `{database}`;"),
        _ => format!("DROP DATABASE IF EXISTS \"{database}\" WITH (FORCE);"),
    };
    server.execute_unprepared(&sql).await.unwrap();
}

/// Postgres only. Postgres refuses to copy a template while another session is
/// connected to it, for example one that is still closing, so this retries.
pub async fn copy_init_db(server: &DatabaseConnection, database: &str) {
    let sql = format!("CREATE DATABASE \"{database}\" TEMPLATE \"{INIT_DB}\";");
    let mut attempts = 0;
    loop {
        match server.execute_unprepared(&sql).await {
            Err(error)
                if attempts < 300
                    && error
                        .to_string()
                        .contains("is being accessed by other users") =>
            {
                attempts += 1;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            result => {
                result.unwrap();
                return;
            }
        }
    }
}

async fn lock(server: &DatabaseConnection) {
    let backend = server.get_database_backend();
    match backend {
        DbBackend::MySql => {
            let acquired: Option<i64> = server
                .query_one_raw(Statement::from_string(
                    backend,
                    format!("SELECT GET_LOCK('{MARIADB_LOCK}', 300);"),
                ))
                .await
                .unwrap()
                .unwrap()
                .try_get_by_index(0)
                .unwrap();
            assert!(
                acquired == Some(1),
                "timed out waiting for the lock on {INIT_DB}"
            );
        }
        _ => {
            server
                .execute_unprepared(&format!("SELECT pg_advisory_lock({POSTGRES_LOCK});"))
                .await
                .unwrap();
        }
    }
}

async fn build(server: &DatabaseConnection, url: &Url) {
    let backend = server.get_database_backend();
    drop_database(server, INIT_DB).await;
    let create = match backend {
        DbBackend::MySql => format!("CREATE DATABASE `{INIT_DB}`;"),
        _ => format!("CREATE DATABASE \"{INIT_DB}\";"),
    };
    server.execute_unprepared(&create).await.unwrap();

    let init_db = sea_orm::Database::connect(with_database(url, INIT_DB))
        .await
        .unwrap();
    run_migrations(&init_db).await.unwrap();
    if backend == DbBackend::Postgres {
        init_db.execute_unprepared(&seed_sql()).await.unwrap();
    }
    init_db.close().await.unwrap();

    if backend == DbBackend::Postgres {
        drop_database(server, INIT_DB_SCHEMA).await;
        copy_init_db(server, INIT_DB_SCHEMA).await;
        mark_ready(server, INIT_DB_SCHEMA).await;
    }
    mark_ready(server, INIT_DB).await;
}

/// Postgres: copies every table with rows into the seed schema, from where the
/// integration tests restore them. `ANALYZE` makes the catalog queries of the
/// schema discovery fast, and every copy of `INIT_DB` inherits the statistics.
fn seed_sql() -> String {
    format!(
        "CREATE SCHEMA {SEED_SCHEMA};
        DO $$
        DECLARE
            name text;
            has_rows boolean;
        BEGIN
            FOR name IN SELECT tablename FROM pg_tables
                WHERE schemaname = 'public' AND tablename <> '{MIGRATION_TABLE}'
            LOOP
                EXECUTE format('SELECT EXISTS (SELECT 1 FROM public.%I)', name) INTO has_rows;
                IF has_rows THEN
                    EXECUTE format('CREATE TABLE {SEED_SCHEMA}.%I AS SELECT * FROM public.%I', name, name);
                END IF;
            END LOOP;
        END $$;
        ANALYZE;"
    )
}

pub fn with_database(url: &Url, database: &str) -> Url {
    let mut url = url.clone();
    url.set_path(database);
    url
}
