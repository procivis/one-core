use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::path::PathBuf;

use clap::Parser;
use one_core::config::core_config::{self, AppConfig};
use sentry::integrations::tracing::EventFilter;
use tracing_subscriber::prelude::*;

use core_server::router::start_server;
use core_server::{build_info, metrics, ServerConfig};

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

    let addr = SocketAddr::new(
        app_config
            .app
            .server_ip
            .unwrap_or(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
        app_config.app.server_port.unwrap_or(3000),
    );

    let listener = TcpListener::bind(addr).expect("Failed to bind to address");

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let db_conn = sql_data_provider::db_conn(&app_config.app.database_url).await;

            start_server(listener, app_config, db_conn).await
        })
}

fn initialize_sentry(config: &ServerConfig) -> Option<sentry::ClientInitGuard> {
    let ServerConfig {
        sentry_dsn,
        sentry_environment,
        ..
    } = config;

    if let (Some(dsn), Some(environment)) = (sentry_dsn, sentry_environment) {
        if dsn.is_empty() {
            return None;
        }

        let guard = sentry::init((
            dsn.to_owned(),
            sentry::ClientOptions {
                release: sentry::release_name!(),
                environment: Some(environment.to_owned().into()),
                max_breadcrumbs: 50,
                traces_sample_rate: 1.0,
                ..Default::default()
            },
        ));

        // This will be inherited when a new hub is created
        sentry::configure_scope(|scope| {
            scope.set_tag("build-target", build_info::BUILD_RUST_CHANNEL);
            scope.set_tag("build-time", build_info::BUILD_TIME);
            scope.set_tag("branch", build_info::BRANCH);
            scope.set_tag("tag", build_info::TAG);
            scope.set_tag("commit", build_info::COMMIT_HASH);
            scope.set_tag("rust-version", build_info::RUST_VERSION);
            scope.set_tag("pipeline-ID", build_info::CI_PIPELINE_ID);
        });

        Some(guard)
    } else {
        None
    }
}

fn initialize_tracing(config: &ServerConfig) {
    // Create a filter based on the log level
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .or_else(|_| {
            tracing_subscriber::EnvFilter::try_new(
                config.trace_level.as_ref().unwrap_or(&"debug".to_string()),
            )
        })
        .expect("Failed to create env filter");

    let sentry_layer = sentry::integrations::tracing::layer().event_filter(|md| {
        match md.level() {
            // error traces report directly to Sentry
            &tracing::Level::ERROR => EventFilter::Event,
            // info/warn traces log as sentry breadcrumb
            &tracing::Level::INFO | &tracing::Level::WARN => EventFilter::Breadcrumb,
            // lower level traces are ignored by sentry
            _ => EventFilter::Ignore,
        }
    });

    let tracing_layer = tracing_subscriber::registry()
        .with(filter)
        .with(sentry_layer);

    if config.trace_json.unwrap_or_default() {
        tracing_layer
            .with(tracing_subscriber::fmt::layer().json().flatten_event(true))
            .init();
    } else {
        tracing_layer.with(tracing_subscriber::fmt::layer()).init();
    };
}
