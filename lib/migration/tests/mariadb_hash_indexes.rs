#![allow(clippy::unwrap_used)]

use migration::test_utilities::{INIT_DB, prepare_init_db, with_database};
use sea_orm::{ConnectionTrait, Database, DbBackend, Statement};
use similar_asserts::assert_eq;

/// MariaDB builds a unique index over a column longer than its key limit as `USING HASH`, and
/// concurrent inserts then deadlock or skip the uniqueness check.
#[tokio::test]
async fn test_hash_unique_indexes_only_on_the_known_tables() {
    let Ok(url) = std::env::var("ONE_app__databaseUrl") else {
        return;
    };
    if !url.starts_with("mysql:") {
        return;
    }
    let url = url.parse().unwrap();
    prepare_init_db(&url).await;
    let db = Database::connect(with_database(&url, INIT_DB))
        .await
        .unwrap();

    let hash_indexes: Vec<String> = db
        .query_all_raw(Statement::from_string(
            DbBackend::MySql,
            "SELECT DISTINCT CONCAT(table_name, '.', index_name) FROM information_schema.statistics \
             WHERE table_schema = DATABASE() AND index_type = 'HASH' ORDER BY 1",
        ))
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.try_get_by_index(0).unwrap())
        .collect();

    // once ONE-11761 is done, list should be empty
    assert_eq!(
        hash_indexes,
        [
            "trust_list_publication.index-TrustPublication-Name-Org-DeactivatedAt-Unique",
            "trust_list_subscription.index-TrustListSubscription-Reference-Col-DeactivatedAt-Unique",
        ]
    );
}
