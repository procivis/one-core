use std::sync::Arc;

use one_core::config::core_config::AppConfig;
use one_core::OneCore;
use sentry::integrations::tracing::EventFilter;
use sql_data_provider::{DataLayer, DbConn};
use tracing_subscriber::prelude::*;

use crate::{build_info, ServerConfig};

pub fn initialize_core(app_config: &AppConfig<ServerConfig>, db_conn: DbConn) -> OneCore {
    OneCore::new(
        |exportable_storages| Arc::new(DataLayer::build(db_conn, exportable_storages)),
        app_config.core.to_owned(),
        Some(app_config.app.core_base_url.to_owned()),
        None,
        app_config.app.json_ld_context.to_owned(),
    )
    .expect("Failed to initialize core")
}

pub fn initialize_sentry(config: &ServerConfig) -> Option<sentry::ClientInitGuard> {
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
            let mut set_tag = |tag: &str, value: &str| {
                if !value.is_empty() {
                    scope.set_tag(tag, value)
                }
            };

            set_tag("build-target", build_info::BUILD_RUST_CHANNEL);
            set_tag("build-time", build_info::BUILD_TIME);
            set_tag("branch", build_info::BRANCH);
            set_tag("tag", build_info::TAG);
            set_tag("commit", build_info::COMMIT_HASH);
            set_tag("rust-version", build_info::RUST_VERSION);
            set_tag("pipeline-ID", build_info::CI_PIPELINE_ID);
        });

        Some(guard)
    } else {
        None
    }
}

pub fn initialize_tracing(config: &ServerConfig) {
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
            // info/warn/error traces log as sentry breadcrumb
            &tracing::Level::INFO | &tracing::Level::WARN | &tracing::Level::ERROR => {
                EventFilter::Breadcrumb
            }
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
