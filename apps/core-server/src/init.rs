use std::{collections::HashMap, sync::Arc};

use one_core::provider::key_algorithm::ml_dsa::MlDsa;
use one_core::provider::key_storage::pkcs11::PKCS11KeyProvider;
use one_core::{config::core_config::AppConfig, DidMethodCreator, OneCoreBuilder};
use one_core::{DataProviderCreator, KeyAlgorithmCreator, KeyStorageCreator, OneCore};

use crate::did_config::{DidMdlParams, DidUniversalParams, DidWebParams};
use crate::{build_info, did_config, ServerConfig};
use one_core::config::core_config::Fields;
use one_core::config::{core_config, ConfigError, ConfigParsingError, ConfigValidationError};
use one_core::provider::did_method::mdl::{DidMdl, DidMdlValidator};
use one_core::provider::did_method::x509::X509Method;
use one_providers::crypto::imp::hasher::sha256::SHA256;
use one_providers::crypto::imp::signer::bbs::BBSSigner;
use one_providers::crypto::imp::signer::crydi3::CRYDI3Signer;
use one_providers::crypto::imp::signer::eddsa::EDDSASigner;
use one_providers::crypto::imp::signer::es256::ES256Signer;
use one_providers::crypto::imp::CryptoProviderImpl;
use one_providers::crypto::{Hasher, Signer};
use one_providers::did::imp::jwk::JWKDidMethod;
use one_providers::did::imp::key::KeyDidMethod;
use one_providers::did::imp::provider::DidMethodProviderImpl;
use one_providers::did::imp::universal::UniversalDidMethod;
use one_providers::did::imp::web::WebDidMethod;
use one_providers::did::DidMethod;
use one_providers::key_algorithm::imp::bbs::BBS;
use one_providers::key_algorithm::imp::eddsa::Eddsa;
use one_providers::key_algorithm::imp::es256::Es256;
use one_providers::key_algorithm::imp::provider::KeyAlgorithmProviderImpl;
use one_providers::key_algorithm::KeyAlgorithm;
use one_providers::key_storage::imp::azure_vault::AzureVaultKeyProvider;
use one_providers::key_storage::imp::internal::InternalKeyProvider;
use one_providers::key_storage::imp::provider::KeyProviderImpl;
use one_providers::key_storage::KeyStorage;
use sentry::integrations::tracing::EventFilter;
use serde_json::json;
use sql_data_provider::{DataLayer, DbConn};
use tracing_subscriber::prelude::*;

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

    let key_storage_creator: KeyStorageCreator = Box::new(|config, providers| {
        let mut key_providers: HashMap<String, Arc<dyn KeyStorage>> = HashMap::new();

        for (name, field) in config.iter() {
            let provider = match field.r#type.as_str() {
                "INTERNAL" => {
                    let params = config
                        .get(name)
                        .expect("Internal key provider config is required");
                    Arc::new(InternalKeyProvider::new(
                        providers
                            .key_algorithm_provider
                            .as_ref()
                            .expect("Missing key algorithm provider")
                            .clone(),
                        params,
                    )) as _
                }
                "PKCS11" => Arc::new(PKCS11KeyProvider::new()) as _,
                "AZURE_VAULT" => {
                    let params = config.get(name).expect("AzureVault config is required");
                    Arc::new(AzureVaultKeyProvider::new(
                        params,
                        providers
                            .crypto
                            .as_ref()
                            .expect("Crypto provider is required")
                            .clone(),
                    )) as _
                }
                other => panic!("Unexpected key storage: {other}"),
            };
            key_providers.insert(name.to_owned(), provider);
        }

        Arc::new(KeyProviderImpl::new(key_providers.to_owned()))
    });

    let storage_creator: DataProviderCreator = Box::new(|| {
        Arc::new(DataLayer::build(
            db_conn,
            vec!["INTERNAL".to_string(), "AZURE_VAULT".to_owned()],
        ))
    });

    let core_base_url = app_config.app.core_base_url.to_owned();
    let did_method_creator: DidMethodCreator = Box::new(move |config, providers| {
        let mut did_mdl_validator: Option<Arc<dyn DidMdlValidator>> = None;

        let mut did_methods: HashMap<String, Arc<dyn DidMethod>> = HashMap::new();

        for (name, field) in config.iter() {
            let did_method: Arc<dyn DidMethod> = match field.r#type.to_string().as_str() {
                "KEY" => {
                    let key_algorithm_provider = providers
                        .key_algorithm_provider
                        .to_owned()
                        .expect("key algorithm provider is required");
                    Arc::new(KeyDidMethod::new(key_algorithm_provider.clone())) as _
                }
                "WEB" => {
                    let params: DidWebParams = config
                        .get(name)
                        .expect("failed to deserialize did web params");
                    let did_web = WebDidMethod::new(&Some(core_base_url.to_owned()), params.into())
                        .map_err(|_| {
                            ConfigError::Validation(ConfigValidationError::KeyNotFound(
                                "Base url".to_string(),
                            ))
                        })
                        .expect("failed to create did web method");
                    Arc::new(did_web) as _
                }
                "JWK" => {
                    let key_algorithm_provider = providers
                        .key_algorithm_provider
                        .to_owned()
                        .expect("key algorithm provider is required");
                    Arc::new(JWKDidMethod::new(key_algorithm_provider.clone())) as _
                }
                "X509" => Arc::new(X509Method::new()) as _,
                "UNIVERSAL_RESOLVER" => {
                    let params: DidUniversalParams = config
                        .get(name)
                        .expect("failed to deserialize did universal params");
                    Arc::new(UniversalDidMethod::new(params.into())) as _
                }
                "MDL" => {
                    let key_algorithm_provider = providers
                        .key_algorithm_provider
                        .to_owned()
                        .expect("key algorithm provider is required");

                    let params: DidMdlParams = config
                        .get(name)
                        .expect("failed to deserialize did mdl params");

                    let did_mdl = DidMdl::new(params.into(), key_algorithm_provider.clone())
                        .map_err(|err| {
                            ConfigParsingError::GeneralParsingError(format!(
                                "Invalid DID MDL config: {err}"
                            ))
                        })
                        .expect("failed to create did mdl method");
                    let did_mdl = Arc::new(did_mdl);

                    did_mdl_validator = Some(did_mdl.clone() as Arc<dyn DidMdlValidator>);

                    did_mdl as _
                }
                other => panic!("Unexpected did method: {other}"),
            };
            did_methods.insert(name.to_owned(), did_method);
        }

        for (key, value) in config.iter_mut() {
            if let Some(entity) = did_methods.get(key) {
                let params = entity.get_keys().map(|keys| {
                    let serializable_keys = did_config::Keys::from(keys);
                    core_config::Params {
                        public: Some(json!({
                            "keys": serializable_keys,
                        })),
                        private: None,
                    }
                });
                let capabilities: did_config::DidCapabilities = entity.get_capabilities().into();

                *value = Fields {
                    capabilities: Some(json!(capabilities)),
                    params,
                    ..value.clone()
                }
            }
        }

        (
            Arc::new(DidMethodProviderImpl::new(did_methods)),
            did_mdl_validator,
        )
    });

    OneCoreBuilder::new(app_config.core.clone())
        .with_base_url(app_config.app.core_base_url.to_owned())
        .with_crypto(crypto)
        .with_data_provider_creator(storage_creator)
        .with_cache_entities_config(app_config.app.cache_entities.to_owned())
        .with_key_algorithm_provider(key_algo_creator)
        .with_key_storage_provider(key_storage_creator)
        .with_did_method_provider(did_method_creator)
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
