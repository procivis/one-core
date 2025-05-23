use std::net::TcpListener;

use core_server::ServerConfig;
use core_server::init::initialize_core;
use core_server::router::start_server;
use one_core::config::core_config::AppConfig;
use sql_data_provider::DbConn;
use tokio::task::JoinHandle;

pub async fn run_server(
    listener: TcpListener,
    config: AppConfig<ServerConfig>,
    db: &DbConn,
) -> JoinHandle<()> {
    let core = initialize_core(&config, db.to_owned()).await;
    tokio::spawn(async move { start_server(listener, config.app, core).await })
}
