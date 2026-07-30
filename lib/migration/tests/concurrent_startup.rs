#![allow(clippy::unwrap_used)]
#![allow(clippy::print_stdout)]

use migration::runner::run_migrations;
use sea_orm::{ConnectionTrait, Database, DatabaseConnection};

const CONCURRENT_STARTUPS: usize = 8;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_first_time_migrations_against_empty_db_all_succeed() {
    let Some(db) = FreshDatabase::create().await else {
        return;
    };

    let mut handles = Vec::with_capacity(CONCURRENT_STARTUPS);
    for instance in 0..CONCURRENT_STARTUPS {
        let url = db.url.clone();
        handles.push(tokio::spawn(async move {
            let conn = Database::connect(url)
                .await
                .map_err(|e| format!("instance {instance}: connect failed: {e}"))?;
            run_migrations(&conn)
                .await
                .map_err(|e| format!("instance {instance}: migration failed: {e}"))
        }));
    }

    let mut failures = Vec::new();
    for handle in handles {
        if let Err(failure) = handle.await.unwrap() {
            failures.push(failure);
        }
    }

    db.drop_database().await;

    assert!(
        failures.is_empty(),
        "{}/{CONCURRENT_STARTUPS} concurrent migrators failed:\n  - {}",
        failures.len(),
        failures.join("\n  - ")
    );
}

struct FreshDatabase {
    admin: DatabaseConnection,
    name: String,
    url: String,
}

impl FreshDatabase {
    async fn create() -> Option<Self> {
        let Ok(cluster_url) = std::env::var("ONE_app__databaseUrl") else {
            println!("skipping, ONE_app__databaseUrl not set");
            return None;
        };
        let mut url: url::Url = cluster_url.parse().unwrap();

        // remove path to connect to the cluster (postgres needs an existing db)
        let mut admin_url = url.clone();
        if cluster_url.starts_with("postgres") {
            admin_url.set_path("/postgres");
        } else if cluster_url.starts_with("mysql") {
            admin_url.set_path("");
        } else {
            println!("skipping, requires a postgres:// or mysql:// URL");
            return None;
        }
        let admin = Database::connect(admin_url.to_string()).await.unwrap();

        let name = format!(
            "concurrent_init_{}",
            ulid::Ulid::new().to_string().to_lowercase()
        );
        println!("USING DATABASE {name}");
        admin
            .execute_unprepared(&format!("CREATE DATABASE {name};"))
            .await
            .unwrap();

        url.set_path(&name);
        Some(Self {
            admin,
            name,
            url: url.to_string(),
        })
    }

    async fn drop_database(self) {
        self.admin
            .execute_unprepared(&format!("DROP DATABASE IF EXISTS {}", self.name))
            .await
            .ok();
    }
}
