use core_server::init::initialize_core;
use core_server::router::start_server;
use core_server::ServerConfig;
use one_core::config::core_config::AppConfig;
use sql_data_provider::DbConn;
use std::net::TcpListener;
use tokio::task::JoinHandle;

pub fn run_server(
    listener: TcpListener,
    config: AppConfig<ServerConfig>,
    db: &DbConn,
) -> JoinHandle<()> {
    let core = initialize_core(&config, db.to_owned());
    tokio::spawn(async move { start_server(listener, config.app, core).await })
}
