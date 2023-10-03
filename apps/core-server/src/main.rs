#![cfg_attr(feature = "strict", deny(warnings))]

use std::net::IpAddr;
use std::panic;
use std::sync::Arc;

use figment::{providers::Env, Figment};
use router::{router_logic, HttpRequestContext, SENTRY_HTTP_REQUEST};
use sentry_tracing::EventFilter;
use serde::Deserialize;
use shadow_rs::shadow;
use tracing::info;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::prelude::*;

pub(crate) mod dto;
pub(crate) mod endpoint;
pub(crate) mod extractor;
pub(crate) mod mapper;
pub(crate) mod router;
pub(crate) mod serialize;

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    config_file: String,
    database_url: String,
    server_ip: Option<IpAddr>,
    server_port: Option<u16>,
    trace_json: Option<bool>,
    auth_token: String,
    core_base_url: String,
    sentry_dsn: Option<String>,
    sentry_environment: Option<String>,
}

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

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async { router_logic(config).await })
        .unwrap()
}

fn log_build_info() {
    shadow!(build);
    info!("Build target: {}", build::BUILD_RUST_CHANNEL);
    info!("Build time: {}", build::BUILD_TIME);
    info!("Branch: {}", build::BRANCH);
    info!("Tag: {}", build::TAG);
    info!("Commit: {}", build::COMMIT_HASH);
    info!("Rust version: {}", build::RUST_VERSION);
    info!("Pipeline ID: {}", build::CI_PIPELINE_ID);
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
