use core_server::ServerConfig;
use one_core::config::core_config::AppConfig;
use serde_json::json;

use crate::fixtures;
use crate::utils::context::TestContext;
use crate::utils::server::run_server;

#[tokio::test]
async fn test_transport_params_are_filtered_in_config() {
    // GIVEN
    let context = TestContext::new().await;

    // WHEN
    let resp = context.api.config.get().await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["transport"]["HTTP"]["params"], json!({}));
}

#[tokio::test]
async fn test_server_starts_with_base_config() {
    let root = std::env!("CARGO_MANIFEST_DIR");
    let configs = [
        format!("{}/../../config/config.yml", root),
        format!("{}/../../config/config-procivis-base.yml", root),
    ]
    .into_iter()
    .map(|path| std::fs::read_to_string(path).unwrap());

    let mut app_config: AppConfig<ServerConfig> =
        AppConfig::from_yaml_str_configs(configs.collect()).unwrap();
    app_config.app = ServerConfig {
        database_url: "sqlite::memory:".into(),
        auth_token: "test".to_string(),
        core_base_url: "http://0.0.0.0:3000".into(),
        trace_level: Some("debug,hyper=error,sea_orm=info,sqlx::query=error".into()),
        hide_error_response_cause: true,
        allow_insecure_http_transport: true,
        insecure_vc_api_endpoints_enabled: true,
        ..Default::default()
    };
    let db_conn = fixtures::create_db(&app_config).await;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    run_server(listener, app_config, &db_conn).await;
}
