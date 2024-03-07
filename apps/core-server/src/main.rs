use clap::Parser;
use core_server::{
    init::{initialize_core, initialize_sentry, initialize_tracing},
    metrics,
    router::start_server,
    ServerConfig,
};
use one_core::{
    config::core_config::{self, AppConfig},
    OneCore,
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    path::PathBuf,
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long, value_name = "FILE")]
    config: Option<Vec<PathBuf>>,
}

fn main() {
    let cli = Cli::parse();

    let mut config_files = cli.config.unwrap_or_default();
    config_files.insert(0, "config/config.yml".into());

    let app_config: AppConfig<ServerConfig> =
        core_config::AppConfig::from_files(&config_files).expect("Failed creating config");

    let _sentry_init_guard = initialize_sentry(&app_config.app);

    initialize_tracing(&app_config.app);
    metrics::setup();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Unable to create tokio runtime")
        .block_on(async {
            let db_conn = sql_data_provider::db_conn(&app_config.app.database_url)
                .await
                .expect("Unable to establish database connection");

            let core = initialize_core(&app_config, db_conn);

            run_server(app_config.app, core).await
        })
}

async fn run_server(config: ServerConfig, core: OneCore) {
    let addr = SocketAddr::new(
        config
            .server_ip
            .unwrap_or(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
        config.server_port.unwrap_or(3000),
    );

    let listener = TcpListener::bind(addr).expect("Failed to bind to address");

    start_server(listener, config, core).await
}
