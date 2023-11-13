#![cfg_attr(feature = "strict", deny(warnings))]

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::panic;
use std::sync::Arc;

use figment::{providers::Env, Figment};
use sentry_tracing::EventFilter;
use tracing::info;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::prelude::*;

use core_server::router::{start_server, HttpRequestContext, SENTRY_HTTP_REQUEST};
use core_server::{build_info, metrics, Config};

fn main() {
    let config: Config = Figment::new()
        .merge(Env::raw())
        .extract()
        .unwrap_or_else(|e| {
            panic!("Failed to parse config: {}", e);
        });

    let _sentry_init_guard = initialize_sentry(&config);

    initialize_tracing(&config);
    log_build_info();
    metrics::setup();

    let addr = SocketAddr::new(
        config
            .server_ip
            .unwrap_or(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
        config.server_port.unwrap_or(3000),
    );
    let listener = TcpListener::bind(addr).expect("Failed to bind to address");

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let db_conn = sql_data_provider::db_conn(&config.database_url).await;

            start_server(listener, config, db_conn).await
        })
}

fn log_build_info() {
    info!("Build target: {}", build_info::BUILD_RUST_CHANNEL);
    info!("Build time: {}", build_info::BUILD_TIME);
    info!("Branch: {}", build_info::BRANCH);
    info!("Tag: {}", build_info::TAG);
    info!("Commit: {}", build_info::COMMIT_HASH);
    info!("Rust version: {}", build_info::RUST_VERSION);
    info!("Pipeline ID: {}", build_info::CI_PIPELINE_ID);
}

fn initialize_sentry(config: &Config) -> Option<sentry::ClientInitGuard> {
    let Config {
        sentry_dsn,
        sentry_environment,
        ..
    } = config;

    if let (Some(dsn), Some(environment)) = (sentry_dsn, sentry_environment) {
        if dsn.is_empty() {
            return None;
        }

        Some(sentry::init((
            dsn.to_owned(),
            sentry::ClientOptions {
                release: sentry::release_name!(),
                environment: Some(environment.to_owned().into()),
                max_breadcrumbs: 50,
                before_send: Some(Arc::new(|mut event| {
                    if event.level == sentry::Level::Error
                        && event
                            .message
                            .as_ref()
                            .is_some_and(|message| message.starts_with("PANIC!"))
                    {
                        event.level = sentry::Level::Fatal;
                    }

                    let _ = SENTRY_HTTP_REQUEST.try_with(|http_request| {
                        let HttpRequestContext {
                            method,
                            path,
                            request_id,
                            session_id,
                        } = http_request;

                        event
                            .tags
                            .insert("http-request".to_string(), format!("{method} {path}"));

                        if let Some(request_id) = request_id {
                            event
                                .tags
                                .insert("ONE-request-id".to_string(), request_id.to_owned());
                        }
                        if let Some(session_id) = session_id {
                            event
                                .tags
                                .insert("ONE-session-id".to_string(), session_id.to_owned());
                        }
                    });

                    Some(event)
                })),
                ..Default::default()
            },
        )))
    } else {
        None
    }
}

fn get_sentry_tracing_layer<
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
>() -> sentry_tracing::SentryLayer<S> {
    sentry_tracing::layer().event_filter(|md| {
        match md.level() {
            // error traces report directly to Sentry
            &tracing::Level::ERROR => EventFilter::Event,
            // info/warn traces log as sentry breadcrumb
            &tracing::Level::INFO | &tracing::Level::WARN => EventFilter::Breadcrumb,
            // lower level traces are ignored by sentry
            _ => EventFilter::Ignore,
        }
    })
}

fn initialize_tracing(config: &Config) {
    // Create a filter based on the log level
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .or_else(|_| tracing_subscriber::EnvFilter::try_new("debug"))
        .expect("Failed to create env filter");

    if config.trace_json.unwrap_or_default() {
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_span_events(FmtSpan::CLOSE)
            .json()
            .flatten_event(true)
            .finish();

        tracing::subscriber::set_global_default(subscriber.with(get_sentry_tracing_layer()))
            .expect("Tracing subscriber initialized.");
    } else {
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_span_events(FmtSpan::CLOSE)
            .finish();

        tracing::subscriber::set_global_default(subscriber.with(get_sentry_tracing_layer()))
            .expect("Tracing subscriber initialized.");
    };

    panic::set_hook(Box::new(|p| {
        tracing::error!("PANIC! Error: {p}");
    }));
}
