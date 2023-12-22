use core_server::router::start_server;
use one_core::model::did::Did;
use one_core::model::organisation::Organisation;
use tokio::task::JoinHandle;

use super::api_clients::Client;
use super::db_clients::DbClient;
use super::mock_server::MockServer;
use crate::fixtures;

pub struct TestContext {
    pub db: DbClient,
    pub api: Client,
    pub server_mock: MockServer,
    _handle: JoinHandle<()>,
}

impl TestContext {
    pub async fn new() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let config = fixtures::create_config(&base_url);
        let db = fixtures::create_db(&config).await;
        let _handle = tokio::spawn({
            let db = db.clone();
            async move { start_server(listener, config, db).await }
        });

        Self {
            db: DbClient::new(db),
            api: Client::new(base_url, "test".into()),
            server_mock: MockServer::new().await,
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
