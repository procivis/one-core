use core_server::ServerConfig;
use one_core::model::did::{Did, KeyRole};
use one_core::model::key::Key;
use one_core::model::organisation::Organisation;
use one_core::{config::core_config::AppConfig, model::did::RelatedKey};
use tokio::task::JoinHandle;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use super::api_clients::Client;
use super::db_clients::keys::es256_testing_params;
use super::db_clients::DbClient;
use super::mock_server::MockServer;
use super::server::run_server;
use crate::fixtures::{self, TestingDidParams};

pub struct TestContext {
    pub db: DbClient,
    pub api: Client,
    pub server_mock: MockServer,
    pub config: AppConfig<ServerConfig>,
    _handle: JoinHandle<()>,
}

impl TestContext {
    pub async fn new() -> Self {
        Self::new_with_token("test").await
    }

    pub async fn new_with_token(token: &str) -> Self {
        let server_mock = MockServer::new().await;
        let stdout_log = tracing_subscriber::fmt::layer().with_test_writer();
        let _ = tracing_subscriber::registry().with(stdout_log).try_init();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());

        let config = fixtures::create_config(&base_url, Some(server_mock.uri()));
        let db = fixtures::create_db(&config).await;
        let _handle = run_server(listener, config.to_owned(), &db);

        Self {
            db: DbClient::new(db),
            api: Client::new(base_url.clone(), token.into()),
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

    pub async fn new_with_did() -> (Self, Organisation, Did, Key) {
        let (context, organisation) = Self::new_with_organisation().await;
        let key = context
            .db
            .keys
            .create(&organisation, es256_testing_params())
            .await;
        let did = context
            .db
            .dids
            .create(
                &organisation,
                TestingDidParams {
                    keys: Some(vec![
                        RelatedKey {
                            role: KeyRole::AssertionMethod,
                            key: key.to_owned(),
                        },
                        RelatedKey {
                            role: KeyRole::Authentication,
                            key: key.to_owned(),
                        },
                        RelatedKey {
                            role: KeyRole::KeyAgreement,
                            key: key.to_owned(),
                        },
                    ]),
                    ..Default::default()
                },
            )
            .await;
        (context, organisation, did, key)
    }
}
