use core_server::{AuthMode, ServerConfig};
use one_core::config::core_config::{AppConfig, InputFormat};
use serde_json::json;
use similar_asserts::assert_eq;

use crate::fixtures;
use crate::utils::context::TestContext;
use crate::utils::server::run_server;

#[tokio::test]
async fn test_transport_params_are_filtered_in_config() {
    // GIVEN
    let context = TestContext::new(None).await;

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

    let set_encryption_key = Some(
        indoc::indoc! {"
        app:
            auth:
                mode: UNSAFE_STATIC
                staticToken: \"test\"
        keyStorage:
            INTERNAL:
                params:
                    private:
                        encryption: \"93d9182795f0d1bec61329fc2d18c4b4c1b7e65e69e20ec30a2101a9875fff7e\"
        issuanceProtocol:
            OPENID4VCI_DRAFT13:
                params:
                    private:
                        encryption: \"93d9182795f0d1bec61329fc2d18c4b4c1b7e65e69e20ec30a2101a9875fff7e\"
            OPENID4VCI_DRAFT13_SWIYU:
                params:
                    private:
                        encryption: \"93d9182795f0d1bec61329fc2d18c4b4c1b7e65e69e20ec30a2101a9875fff7e\"
            OPENID4VCI_FINAL1:
                params:
                    private:
                        encryption: \"93d9182795f0d1bec61329fc2d18c4b4c1b7e65e69e20ec30a2101a9875fff7e\"
                        nonce:
                            signingKey: \"93d9182795f0d1bec61329fc2d18c4b4c1b7e65e69e20ec30a2101a9875fff7e\"
    "}.to_string(),
    );
    let configs = [
        InputFormat::yaml_file(format!("{root}/../../config/config.yml")),
        InputFormat::yaml_file(format!("{root}/../../config/config-procivis-base.yml")),
    ]
    .into_iter()
    .chain(set_encryption_key.map(InputFormat::yaml_str));

    let mut app_config: AppConfig<ServerConfig> = AppConfig::parse(configs).unwrap();
    let database_url = app_config.app.database_url;
    app_config.app = ServerConfig {
        database_url: if database_url.is_empty() {
            "sqlite::memory:".to_string()
        } else {
            database_url
        },
        server_ip: Default::default(),
        server_port: Default::default(),
        trace_json: Default::default(),
        core_base_url: "http://0.0.0.0:3000".into(),
        sentry_dsn: Default::default(),
        sentry_environment: Default::default(),
        trace_level: Some("debug,hyper=error,sea_orm=info,sqlx::query=error".into()),
        hide_error_response_cause: true,
        allow_insecure_http_transport: true,
        insecure_vc_api_endpoints_enabled: true,
        enable_metrics: Default::default(),
        enable_server_info: Default::default(),
        enable_open_api: Default::default(),
        enable_external_endpoints: Default::default(),
        enable_management_endpoints: Default::default(),
        enable_wallet_provider: Default::default(),
        auth: AuthMode::UnsafeStatic {
            static_token: "test".to_string(),
        },
    };
    let db_conn = fixtures::create_db(&app_config).await;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    run_server(listener, app_config, &db_conn).await;
}
