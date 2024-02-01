use core_server::router::start_server;
use core_server::ServerConfig;
use one_core::config::core_config::AppConfig;
use one_core::model::did::Did;
use one_core::model::organisation::Organisation;
use tokio::task::JoinHandle;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use super::api_clients::Client;
use super::db_clients::DbClient;
use super::mock_server::MockServer;
use crate::fixtures;

pub struct TestContext {
    pub db: DbClient,
    pub api: Client,
    pub server_mock: MockServer,
    pub config: AppConfig<ServerConfig>,
    _handle: JoinHandle<()>,
}

impl TestContext {
    pub async fn new() -> Self {
        let server_mock = MockServer::new().await;
        let stdout_log = tracing_subscriber::fmt::layer().with_test_writer();
        let _ = tracing_subscriber::registry().with(stdout_log).try_init();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());

        let config = fixtures::create_config(&base_url, Some(server_mock.uri()));
        let db = fixtures::create_db(&config).await;
        let config_clone = config.clone();
        let _handle = tokio::spawn({
            let db = db.clone();
            async move { start_server(listener, config_clone, db).await }
        });

        Self {
            db: DbClient::new(db),
            api: Client::new(base_url.clone(), "test".into()),
            server_mock,
            config,
            _handle,
        }
    }

    pub async fn new_with_organisation() -> (Self, Organisation) {
        let context = Self::new().await;
        let organisation = context.db.organisations.create().await;
        (context, organisation)
    }

    pub async fn new_with_did() -> (Self, Organisation, Did) {
        let (context, organisation) = Self::new_with_organisation().await;
        let did = context
            .db
            .dids
            .create(&organisation, Default::default())
            .await;
        (context, organisation, did)
    }
}
