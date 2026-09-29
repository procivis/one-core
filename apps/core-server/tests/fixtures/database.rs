//! Databases for the integration tests.
//!
//! SQLite: every test gets an in-memory copy of one migrated image, cached in the
//! temp directory per migration fingerprint.
//!
//! MariaDB and Postgres need nextest, which runs every test in its own process.
//! A test uses the database of its nextest slot and locks it until the process
//! ends. The first test of a slot copies `INIT_DB` (`migration::test_utilities`)
//! and sets the migration fingerprint as the database comment. Later tests find
//! the fingerprint, empty the tables with rows and restore the rows the
//! migrations inserted.

use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};

use migration::test_utilities::{
    INIT_DB, MIGRATION_TABLE, SEED_SCHEMA, copy_init_db, drop_database, is_ready, mark_ready,
    prepare_init_db, with_database,
};
use sea_orm::sqlx::sqlite::SqliteOwnedBuf;
use sea_orm::sqlx::{AssertSqlSafe, Executor, query_scalar, raw_sql};
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement};
use sql_data_provider::DbConn;
use url::Url;

static SQLITE_IMAGE: tokio::sync::OnceCell<Vec<u8>> = tokio::sync::OnceCell::const_new();

pub async fn create_db() -> DbConn {
    match std::env::var("ONE_app__databaseUrl").ok() {
        Some(url) if url.starts_with("mysql") || url.starts_with("postgres") => {
            server_db(url.parse().unwrap()).await
        }
        // Allows to run API test locally against persistent SQLite DB using e.g.
        // ONE_app__databaseUrl="sqlite://database.sqlite3?mode=rwc";RUST_BACKTRACE=1
        Some(url) => sql_data_provider::db_conn(url, true).await.unwrap(),
        None => sqlite().await,
    }
}

/// Every test gets an in-memory database deserialized from one migrated image.
/// The image is built once per migration set and kept in the temp directory, so
/// the migrations run once per machine instead of once per test process.
async fn sqlite() -> DbConn {
    let image = SQLITE_IMAGE.get_or_init(sqlite_image).await;

    let new_db = sql_data_provider::db_conn("sqlite::memory:", false)
        .await
        .unwrap();
    let mut new_conn = new_db.get_sqlite_connection_pool().acquire().await.unwrap();
    new_conn
        .deserialize(
            None,
            SqliteOwnedBuf::try_from(image.as_slice()).unwrap(),
            false,
        )
        .await
        .unwrap();
    new_db
}

async fn sqlite_image() -> Vec<u8> {
    let path = std::env::temp_dir().join(format!(
        "one-core-tests-sqlite-{}.db",
        migration::migration_fingerprint()
    ));
    if let Ok(image) = std::fs::read(&path) {
        return image;
    }

    let init_db = sql_data_provider::db_conn("sqlite::memory:", true)
        .await
        .unwrap();
    let mut init_conn = init_db
        .get_sqlite_connection_pool()
        .acquire()
        .await
        .unwrap();
    let image = init_conn.serialize(None).await.unwrap().to_vec();

    // Other test processes may write the image at the same time; the rename is atomic.
    let staging = path.with_extension(format!("db.{}", std::process::id()));
    std::fs::write(&staging, &image).unwrap();
    std::fs::rename(&staging, &path).unwrap();
    image
}

async fn server_db(url: Url) -> DbConn {
    let database = slot_database();
    prepare_init_db(&url).await;
    let server = sea_orm::Database::connect(with_database(&url, ""))
        .await
        .unwrap();
    lock_slot(&server, &database).await;

    let backend = server.get_database_backend();
    let ready = is_ready(&server, &database).await;
    if !ready {
        drop_database(&server, &database).await;
        match backend {
            DbBackend::MySql => mariadb::create(&server, &url, &database).await,
            _ => copy_init_db(&server, &database).await,
        }
    }
    let db = sql_data_provider::db_conn(with_database(&url, &database), false)
        .await
        .unwrap();
    match backend {
        DbBackend::MySql => mariadb::reset(&db).await,
        _ => postgres::reset(&db).await,
    }
    if !ready {
        mark_ready(&server, &database).await;
    }
    db
}

/// The next database of this nextest slot. Nextest runs one test per slot at a time.
/// Some tests create more than one database: the later ones get the suffixes `_1`, `_2`.
/// The name carries a hash of the checkout, so runs from two checkouts against one
/// server keep their own slot databases.
fn slot_database() -> String {
    static CREATED: AtomicUsize = AtomicUsize::new(0);
    let Ok(slot) = std::env::var("NEXTEST_TEST_GLOBAL_SLOT") else {
        panic!(
            "the database tests on MariaDB and Postgres need nextest: \
             `cargo nextest run` or `makers integration-tests`"
        );
    };
    let mut hasher = DefaultHasher::new();
    env!("CARGO_MANIFEST_DIR").hash(&mut hasher);
    let checkout = hasher.finish() % 0x1_0000_0000;
    match CREATED.fetch_add(1, Ordering::Relaxed) {
        0 => format!("one_core_test_{checkout:08x}_slot_{slot}"),
        index => format!("one_core_test_{checkout:08x}_slot_{slot}_{index}"),
    }
}

/// Two test runs from one checkout against one server must not share a slot
/// database. The lock connection stays open until the process ends. The previous
/// test of the slot releases the lock when its process ends, which the server may
/// notice a moment later.
async fn lock_slot(server: &DatabaseConnection, database: &str) {
    let result = match server.get_database_backend() {
        DbBackend::MySql => {
            let mut connection = server
                .get_mysql_connection_pool()
                .acquire()
                .await
                .unwrap()
                .detach();
            let result = query_scalar::<_, Option<i64>>(AssertSqlSafe(format!(
                "SELECT GET_LOCK('{database}', 10);"
            )))
            .fetch_one(&mut connection)
            .await
            .map(|acquired| acquired == Some(1));
            std::mem::forget(connection);
            result
        }
        _ => {
            let mut connection = server
                .get_postgres_connection_pool()
                .acquire()
                .await
                .unwrap()
                .detach();
            let result = connection
                .execute(raw_sql(AssertSqlSafe(format!(
                    "SET lock_timeout = '10s'; SELECT pg_advisory_lock(hashtext('{database}'));"
                ))))
                .await
                .map(|_| true);
            std::mem::forget(connection);
            result
        }
    };
    match result {
        Ok(true) => {}
        Ok(false) => panic!(
            "{database} is in use by another test run from this checkout, gave up after 10 s"
        ),
        Err(error) => panic!(
            "could not lock {database}, is another test run from this checkout using it? {error}"
        ),
    }
}

async fn query_strings(db: &DatabaseConnection, sql: String) -> Vec<String> {
    db.query_all_raw(Statement::from_string(db.get_database_backend(), sql))
        .await
        .unwrap()
        .iter()
        .map(|row| row.try_get_by_index(0).unwrap())
        .collect()
}

mod mariadb {
    use super::*;

    /// Creates the tables of `INIT_DB` and copies the migration table. `reset`
    /// adds the other rows.
    pub async fn create(server: &DatabaseConnection, url: &Url, database: &str) {
        server
            .execute_unprepared(&format!("CREATE DATABASE `{database}`;"))
            .await
            .unwrap();
        let tables = query_strings(
            server,
            format!(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = '{INIT_DB}';"
            ),
        )
        .await;
        let mut batch = String::from("SET FOREIGN_KEY_CHECKS = 0;\n");
        for table in tables {
            let create: String = server
                .query_one_raw(Statement::from_string(
                    DbBackend::MySql,
                    format!("SHOW CREATE TABLE `{INIT_DB}`.`{table}`;"),
                ))
                .await
                .unwrap()
                .unwrap()
                .try_get_by_index(1)
                .unwrap();
            batch.push_str(&format!("{create};\n"));
        }
        batch.push_str(&format!(
            "INSERT INTO `{MIGRATION_TABLE}` SELECT * FROM `{INIT_DB}`.`{MIGRATION_TABLE}`;\n\
             SET FOREIGN_KEY_CHECKS = 1;"
        ));
        let db = sea_orm::Database::connect(with_database(url, database))
            .await
            .unwrap();
        db.execute_unprepared(&batch).await.unwrap();
        db.close().await.unwrap();
    }

    /// Empties the tables that have rows here or in `INIT_DB` and copies the rows of
    /// `INIT_DB` back in: one query finds the tables, one batch resets them.
    pub async fn reset(db: &DatabaseConnection) {
        let tables = query_strings(
            db,
            format!(
                "SELECT table_name FROM information_schema.tables \
                 WHERE table_schema = DATABASE() AND table_name <> '{MIGRATION_TABLE}';"
            ),
        )
        .await;
        let with_rows: Vec<String> = tables
            .iter()
            .map(|table| {
                format!(
                    "SELECT '{table}' FROM DUAL WHERE EXISTS (SELECT 1 FROM `{table}`) \
                     OR EXISTS (SELECT 1 FROM `{INIT_DB}`.`{table}`)"
                )
            })
            .collect();
        let tables = query_strings(db, format!("{};", with_rows.join(" UNION ALL "))).await;

        let mut batch = String::from("SET FOREIGN_KEY_CHECKS = 0;\nSTART TRANSACTION;\n");
        for table in tables {
            batch.push_str(&format!(
                "DELETE FROM `{table}`;\nINSERT INTO `{table}` SELECT * FROM `{INIT_DB}`.`{table}`;\n"
            ));
        }
        batch.push_str("COMMIT;\nSET FOREIGN_KEY_CHECKS = 1;");
        db.execute_unprepared(&batch).await.unwrap();
    }
}

mod postgres {
    use super::*;

    /// Empties the tables with rows and copies the rows of the seed schema back in.
    /// One statement deletes from all of them: Postgres checks the NO ACTION foreign
    /// keys at the end of the statement, so the order does not matter.
    pub async fn reset(db: &DatabaseConnection) {
        let tables = query_strings(
            db,
            format!(
                "SELECT tablename FROM pg_tables \
                 WHERE schemaname = 'public' AND tablename <> '{MIGRATION_TABLE}';"
            ),
        )
        .await;
        let with_rows: Vec<String> = tables
            .iter()
            .map(|table| format!("SELECT '{table}' WHERE EXISTS (SELECT 1 FROM \"{table}\")"))
            .collect();
        let used = query_strings(db, format!("{};", with_rows.join(" UNION ALL "))).await;
        let seeded = query_strings(
            db,
            format!("SELECT tablename FROM pg_tables WHERE schemaname = '{SEED_SCHEMA}';"),
        )
        .await;

        let mut statements = vec!["BEGIN;".to_string()];
        if !used.is_empty() {
            let deletes: Vec<String> = used
                .iter()
                .enumerate()
                .map(|(index, table)| format!("d{index} AS (DELETE FROM \"{table}\")"))
                .collect();
            statements.push(format!("WITH {} SELECT 1;", deletes.join(", ")));
        }
        for table in seeded {
            statements.push(format!(
                "INSERT INTO public.\"{table}\" SELECT * FROM \"{SEED_SCHEMA}\".\"{table}\";"
            ));
        }
        statements.push("COMMIT;".to_string());
        db.execute_unprepared(&statements.join("\n")).await.unwrap();
    }
}
