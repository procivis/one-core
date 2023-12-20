use core_server::router::start_server;
use tokio::task::JoinHandle;

use crate::fixtures;

use super::{api_client::Client, db_client::DbClient};

pub struct TestContext {
    pub db: DbClient,
    pub api_client: Client,
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
            api_client: Client::new(base_url, "test".into()),
            _handle,
        }
    }
}
