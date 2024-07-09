use std::{collections::HashMap, sync::Arc};

use one_core::provider::key_algorithm::ml_dsa::MlDsa;
use one_core::{config::core_config::AppConfig, OneCoreBuilder};
use one_core::{DataProviderCreator, KeyAlgorithmCreator, OneCore};

use one_providers::crypto::imp::hasher::sha256::SHA256;
use one_providers::crypto::imp::signer::bbs::BBSSigner;
use one_providers::crypto::imp::signer::crydi3::CRYDI3Signer;
use one_providers::crypto::imp::signer::eddsa::EDDSASigner;
use one_providers::crypto::imp::signer::es256::ES256Signer;
use one_providers::crypto::imp::CryptoProviderImpl;
use one_providers::crypto::{Hasher, Signer};
use one_providers::key_algorithm::imp::bbs::BBS;
use one_providers::key_algorithm::imp::eddsa::Eddsa;
use one_providers::key_algorithm::imp::es256::Es256;
use one_providers::key_algorithm::imp::provider::KeyAlgorithmProviderImpl;
use one_providers::key_algorithm::KeyAlgorithm;
use sentry::integrations::tracing::EventFilter;
use sql_data_provider::{DataLayer, DbConn};
use tracing_subscriber::prelude::*;

use crate::{build_info, ServerConfig};

pub fn initialize_core(app_config: &AppConfig<ServerConfig>, db_conn: DbConn) -> OneCore {
    let hashers: Vec<(String, Arc<dyn Hasher>)> =
        vec![("sha-256".to_string(), Arc::new(SHA256 {}))];

    let signers: Vec<(String, Arc<dyn Signer>)> = vec![
        ("Ed25519".to_string(), Arc::new(EDDSASigner {})),
        ("ES256".to_string(), Arc::new(ES256Signer {})),
        ("CRYDI3".to_string(), Arc::new(CRYDI3Signer {})),
        ("BBS".to_string(), Arc::new(BBSSigner {})),
    ];

    // TODO figure out a better way to initialize crypto
    let crypto = Arc::new(CryptoProviderImpl::new(
        HashMap::from_iter(hashers),
        HashMap::from_iter(signers),
    ));

    let storage_creator: DataProviderCreator =
        Box::new(|exportable_storages| Arc::new(DataLayer::build(db_conn, exportable_storages)));

    let key_algo_creator: KeyAlgorithmCreator = Box::new(|config, providers| {
        let mut key_algorithms: HashMap<String, Arc<dyn KeyAlgorithm>> = HashMap::new();

        for (name, field) in config.iter() {
            let key_algorithm: Arc<dyn KeyAlgorithm> = match field.r#type.as_str() {
                "EDDSA" => {
                    let params = config.get(name).expect("EDDSA config is required");
                    Arc::new(Eddsa::new(params))
                }
                "ES256" => {
                    let params = config.get(name).expect("ES256 config is required");
                    Arc::new(Es256::new(params))
                }
                "BBS_PLUS" => Arc::new(BBS),
                "DILITHIUM" => {
                    let params = config.get(name).expect("DILITHIUM config is required");
                    Arc::new(MlDsa::new(params))
                }
                other => panic!("Unexpected key algorithm: {other}"),
            };
            key_algorithms.insert(name.to_owned(), key_algorithm);
        }

        Arc::new(KeyAlgorithmProviderImpl::new(
            key_algorithms,
            providers
                .crypto
                .as_ref()
                .expect("Crypto is required")
                .clone(),
        ))
    });

    OneCoreBuilder::new(app_config.core.clone())
        .with_base_url(app_config.app.core_base_url.to_owned())
        .with_crypto(crypto)
        .with_data_provider_creator(storage_creator)
        .with_json_ld_context(app_config.app.json_ld_context.to_owned())
        .with_key_algorithm_provider(key_algo_creator)
        .build()
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
