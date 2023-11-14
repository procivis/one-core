use core_server::Config;
use shared_types::DidId;
use sql_data_provider::{self, test_utilities::*, DbConn};
use uuid::Uuid;

pub fn create_config(core_base_url: impl Into<String>) -> Config {
    Config {
        config_file: "../../config.yml".to_string(),
        database_url: "sqlite::memory:".to_string(),
        auth_token: "test".to_string(),
        core_base_url: core_base_url.into(),
        server_ip: None,
        server_port: None,
        trace_json: None,
        sentry_dsn: None,
        sentry_environment: None,
    }
}

pub async fn create_db(config: &Config) -> DbConn {
    sql_data_provider::db_conn(&config.database_url).await
}

pub async fn create_did_key(db_conn: &DbConn) -> DidId {
    let did_id = Uuid::new_v4().to_string().parse().unwrap();

    let organization_id = insert_organisation_to_database(db_conn, None)
        .await
        .unwrap();
    let _key_id = insert_key_to_database(db_conn, &organization_id)
        .await
        .unwrap();

    insert_did(db_conn, "test-did-key", did_id, &organization_id)
        .await
        .unwrap()
}
