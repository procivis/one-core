use std::collections::HashMap;
use std::sync::Arc;

use one_core::config::core_config::{
    AppConfig, CacheEntitiesConfig, CacheEntityCacheType, CacheEntityConfig, Fields, Params,
    RevocationType,
};
use one_core::config::{core_config, ConfigError, ConfigParsingError, ConfigValidationError};
use one_core::provider::caching_loader::json_schema::{JsonSchemaCache, JsonSchemaResolver};
use one_core::provider::caching_loader::trust_list::{TrustListCache, TrustListResolver};
use one_core::provider::caching_loader::vct::{VctTypeMetadataCache, VctTypeMetadataResolver};
use one_core::provider::credential_formatter::json_ld::context::caching_loader::JsonLdCachingLoader;
use one_core::provider::credential_formatter::json_ld_bbsplus::JsonLdBbsplus;
use one_core::provider::credential_formatter::json_ld_classic::JsonLdClassic;
use one_core::provider::credential_formatter::jwt_formatter::JWTFormatter;
use one_core::provider::credential_formatter::mdoc_formatter::MdocFormatter;
use one_core::provider::credential_formatter::physical_card::PhysicalCardFormatter;
use one_core::provider::credential_formatter::provider::CredentialFormatterProviderImpl;
use one_core::provider::credential_formatter::sdjwt_formatter::SDJWTFormatter;
use one_core::provider::credential_formatter::sdjwtvc_formatter::SDJWTVCFormatter;
use one_core::provider::credential_formatter::CredentialFormatter;
use one_core::provider::did_method::jwk::JWKDidMethod;
use one_core::provider::did_method::key::KeyDidMethod;
use one_core::provider::did_method::mdl::{DidMdl, DidMdlValidator};
use one_core::provider::did_method::provider::DidMethodProviderImpl;
use one_core::provider::did_method::resolver::DidCachingLoader;
use one_core::provider::did_method::sd_jwt_vc_issuer_metadata::SdJwtVcIssuerMetadataDidMethod;
use one_core::provider::did_method::universal::UniversalDidMethod;
use one_core::provider::did_method::web::WebDidMethod;
use one_core::provider::did_method::x509::X509Method;
use one_core::provider::did_method::DidMethod;
use one_core::provider::http_client::reqwest_client::ReqwestClient;
use one_core::provider::http_client::HttpClient;
use one_core::provider::key_algorithm::bbs::BBS;
use one_core::provider::key_algorithm::eddsa::Eddsa;
use one_core::provider::key_algorithm::es256::Es256;
use one_core::provider::key_algorithm::ml_dsa::MlDsa;
use one_core::provider::key_algorithm::model::KeyAlgorithmCapabilities;
use one_core::provider::key_algorithm::provider::KeyAlgorithmProviderImpl;
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_storage::azure_vault::AzureVaultKeyProvider;
use one_core::provider::key_storage::internal::InternalKeyProvider;
use one_core::provider::key_storage::pkcs11::PKCS11KeyProvider;
use one_core::provider::key_storage::provider::KeyProviderImpl;
use one_core::provider::key_storage::KeyStorage;
use one_core::provider::mqtt_client::rumqttc_client::RumqttcClient;
use one_core::provider::remote_entity_storage::db_storage::DbStorage;
use one_core::provider::remote_entity_storage::in_memory::InMemoryStorage;
use one_core::provider::remote_entity_storage::{RemoteEntityStorage, RemoteEntityType};
use one_core::provider::revocation::bitstring_status_list::resolver::StatusListCachingLoader;
use one_core::provider::revocation::bitstring_status_list::BitstringStatusList;
use one_core::provider::revocation::lvvc::LvvcProvider;
use one_core::provider::revocation::mdoc_mso_update_suspension::MdocMsoUpdateSuspensionRevocation;
use one_core::provider::revocation::none::NoneRevocation;
use one_core::provider::revocation::provider::RevocationMethodProviderImpl;
use one_core::provider::revocation::status_list_2021::StatusList2021;
use one_core::provider::revocation::token_status_list::TokenStatusList;
use one_core::provider::revocation::RevocationMethod;
use one_core::repository::remote_entity_cache_repository::RemoteEntityCacheRepository;
use one_core::repository::DataRepository;
use one_core::{
    DataProviderCreator, DidMethodCreator, FormatterProviderCreator, KeyAlgorithmCreator,
    KeyStorageCreator, OneCore, OneCoreBuilder, RevocationMethodCreator,
};
use one_crypto::hasher::sha256::SHA256;
use one_crypto::signer::bbs::BBSSigner;
use one_crypto::signer::crydi3::CRYDI3Signer;
use one_crypto::signer::eddsa::EDDSASigner;
use one_crypto::signer::es256::ES256Signer;
use one_crypto::{CryptoProviderImpl, Hasher, Signer};
use sentry::integrations::tracing::EventFilter;
use serde_json::json;
use sql_data_provider::{DataLayer, DbConn};
use time::Duration;
use tracing_subscriber::prelude::*;

use crate::did_config::{DidMdlParams, DidUniversalParams, DidWebParams};
use crate::{build_info, did_config, ServerConfig};

pub async fn initialize_core(app_config: &AppConfig<ServerConfig>, db_conn: DbConn) -> OneCore {
    let reqwest_client = reqwest::Client::builder()
        .https_only(!app_config.app.allow_insecure_http_transport)
        .build()
        .expect("Failed to create reqwest::Client");

    let client: Arc<dyn HttpClient> = Arc::new(ReqwestClient::new(reqwest_client));

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

        for (key, value) in config.iter_mut() {
            if let Some(entity) = key_algorithms.get(key) {
                value.capabilities = Some(json!(Into::<KeyAlgorithmCapabilities>::into(
                    entity.get_capabilities()
                )));
            }
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

    let data_repository = Arc::new(DataLayer::build(
        db_conn,
        vec!["INTERNAL".to_string(), "AZURE_VAULT".to_owned()],
    ));

    let storage_creator: DataProviderCreator = {
        let data_repository = data_repository.clone();
        Box::new(move || data_repository)
    };

    let cache_entities_config = app_config.core.cache_entities.to_owned();
    let core_base_url = app_config.app.core_base_url.to_owned();
    let data_provider = data_repository.clone();
    let did_method_creator: DidMethodCreator = {
        let client = client.clone();
        Box::new(move |config, providers| {
            let mut did_mdl_validator: Option<Arc<dyn DidMdlValidator>> = None;
            let mut url_did_resolver: Option<Arc<dyn DidMethod>> = None;

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
                        let did_web = WebDidMethod::new(
                            &Some(core_base_url.to_owned()),
                            client.clone(),
                            params.into(),
                        )
                        .map_err(|_| {
                            ConfigError::Validation(ConfigValidationError::EntryNotFound(
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
                        Arc::new(UniversalDidMethod::new(params.into(), client.clone())) as _
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
                    "SD_JWT_VC_ISSUER_METADATA" => {
                        let did_method =
                            Arc::new(SdJwtVcIssuerMetadataDidMethod::new(client.clone()));

                        url_did_resolver = Some(did_method.clone() as Arc<dyn DidMethod>);

                        did_method as _
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
                    let capabilities: did_config::DidCapabilities =
                        entity.get_capabilities().into();

                    *value = Fields {
                        capabilities: Some(json!(capabilities)),
                        params,
                        ..value.clone()
                    }
                }
            }

            let did_caching_loader =
                initialize_did_caching_loader(&cache_entities_config, data_provider);

            (
                Arc::new(DidMethodProviderImpl::new(
                    did_caching_loader,
                    did_methods,
                    url_did_resolver,
                )),
                did_mdl_validator,
            )
        })
    };

    let key_storage_creator: KeyStorageCreator = {
        let client = client.clone();
        Box::new(move |config, providers| {
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
                            client.clone(),
                        )) as _
                    }
                    other => panic!("Unexpected key storage: {other}"),
                };
                key_providers.insert(name.to_owned(), provider);
            }

            for (key, value) in config.iter_mut() {
                if let Some(entity) = key_providers.get(key) {
                    value.capabilities = Some(json!(entity.get_capabilities()));
                }
            }

            Arc::new(KeyProviderImpl::new(key_providers.to_owned()))
        })
    };

    let caching_loader =
        initialize_jsonld_cache_loader(&app_config.core.cache_entities, data_repository.clone());

    let formatter_provider_creator: FormatterProviderCreator = {
        let caching_loader = caching_loader.clone();
        let client = client.clone();
        Box::new(move |format_config, datatype_config, providers| {
            let mut formatters: HashMap<String, Arc<dyn CredentialFormatter>> = HashMap::new();

            let did_method_provider = providers
                .did_method_provider
                .as_ref()
                .expect("Did method provider is mandatory");

            let key_algorithm_provider = providers
                .key_algorithm_provider
                .as_ref()
                .expect("Key algorithm provider is mandatory");

            let crypto = providers
                .crypto
                .as_ref()
                .expect("Crypto provider is mandatory");

            for (name, field) in format_config.iter() {
                let formatter = match field.r#type.as_str() {
                    "JWT" => {
                        let params = format_config
                            .get(name)
                            .expect("JWT formatter params are mandatory");
                        Arc::new(JWTFormatter::new(params)) as _
                    }
                    "PHYSICAL_CARD" => Arc::new(PhysicalCardFormatter::new(
                        crypto.clone(),
                        caching_loader.clone(),
                        client.clone(),
                    )) as _,
                    "SD_JWT" => {
                        let params = format_config
                            .get(name)
                            .expect("SD_JWT formatter params are mandatory");
                        Arc::new(SDJWTFormatter::new(params, crypto.clone())) as _
                    }
                    "SD_JWT_VC" => {
                        let params = format_config
                            .get(name)
                            .expect("SD-JWT VC formatter params are mandatory");
                        Arc::new(SDJWTVCFormatter::new(params, crypto.clone())) as _
                    }
                    "JSON_LD_CLASSIC" => {
                        let params = format_config
                            .get(name)
                            .expect("JSON_LD_CLASSIC formatter params are mandatory");
                        Arc::new(JsonLdClassic::new(
                            params,
                            crypto.clone(),
                            providers.core_base_url.clone(),
                            did_method_provider.clone(),
                            caching_loader.clone(),
                            client.clone(),
                        )) as _
                    }
                    "JSON_LD_BBSPLUS" => {
                        let params = format_config
                            .get(name)
                            .expect("JSON_LD_BBSPLUS formatter params are mandatory");
                        Arc::new(JsonLdBbsplus::new(
                            params,
                            crypto.clone(),
                            providers.core_base_url.clone(),
                            did_method_provider.clone(),
                            key_algorithm_provider.clone(),
                            caching_loader.clone(),
                            client.clone(),
                        )) as _
                    }
                    "MDOC" => {
                        let params = format_config
                            .get(name)
                            .expect("MDOC formatter params are mandatory");
                        Arc::new(MdocFormatter::new(
                            params,
                            providers.did_mdl_validator.clone(),
                            did_method_provider.clone(),
                            key_algorithm_provider.clone(),
                            providers.core_base_url.clone(),
                            datatype_config.clone(),
                        )) as _
                    }
                    other => unimplemented!("formatter: {other}"),
                };
                formatters.insert(name.to_owned(), formatter);
            }

            for (key, value) in format_config.iter_mut() {
                if let Some(entity) = formatters.get(key) {
                    value.capabilities = Some(json!(entity.get_capabilities()));
                    if let Some(params) = &mut value.params {
                        if let Some(public) = &mut params.public {
                            if public["embedLayoutProperties"].is_null() {
                                public["embedLayoutProperties"] = false.into();
                            }
                        } else {
                            params.public = Some(json!({
                                "embedLayoutProperties": false
                            }));
                        }
                    } else {
                        value.params = Some(Params {
                            private: None,
                            public: Some(json!({
                                "embedLayoutProperties": false
                            })),
                        });
                    };
                }
            }

            Arc::new(CredentialFormatterProviderImpl::new(formatters))
        })
    };

    let vct_type_metadata_cache = Arc::new(
        initialize_vct_type_metadata_cache(
            &app_config.core.cache_entities,
            data_repository.get_remote_entity_cache_repository().clone(),
            client.clone(),
        )
        .await,
    );

    let json_schema_cache = Arc::new(
        initialize_json_schema_loader(
            &app_config.core.cache_entities,
            data_repository.get_remote_entity_cache_repository(),
            client.clone(),
        )
        .await,
    );

    let trust_list_cache = Arc::new(
        initialize_trust_list_cache(
            &app_config.core.cache_entities,
            data_repository.get_remote_entity_cache_repository(),
            client.clone(),
        )
        .await,
    );

    let cache_entities_config = app_config.core.cache_entities.to_owned();
    let core_base_url = app_config.app.core_base_url.to_owned();
    let revocation_method_creator: RevocationMethodCreator = {
        let client = client.clone();
        Box::new(move |config, providers| {
            let mut revocation_methods: HashMap<String, Arc<dyn RevocationMethod>> = HashMap::new();

            let did_method_provider = providers
                .did_method_provider
                .as_ref()
                .expect("Did method provider is mandatory");

            let key_algorithm_provider = providers
                .key_algorithm_provider
                .as_ref()
                .expect("Key algorithm provider is mandatory");

            let key_provider = providers
                .key_storage_provider
                .clone()
                .expect("Key storage provider is mandatory");

            let formatter_provider = providers
                .formatter_provider
                .clone()
                .expect("Credential formatter provider is mandatory");

            for (key, fields) in config.iter() {
                if fields.disabled() {
                    continue;
                }

                let revocation_method = match fields.r#type {
                    RevocationType::None => Arc::new(NoneRevocation {}) as _,
                    RevocationType::MdocMsoUpdateSuspension => {
                        Arc::new(MdocMsoUpdateSuspensionRevocation {}) as _
                    }
                    RevocationType::BitstringStatusList => {
                        let params = config
                            .get(key)
                            .expect("failed to get BitstringStatusList params");

                        Arc::new(BitstringStatusList::new(
                            Some(core_base_url.clone()),
                            key_algorithm_provider.clone(),
                            did_method_provider.clone(),
                            key_provider.clone(),
                            initialize_statuslist_loader(
                                &cache_entities_config,
                                data_repository.clone(),
                            ),
                            formatter_provider.clone(),
                            client.clone(),
                            Some(params),
                        )) as _
                    }
                    RevocationType::Lvvc => {
                        ({
                            let params = config.get(key).expect("failed to get LVVC params");
                            Arc::new(LvvcProvider::new(
                                Some(core_base_url.clone()),
                                formatter_provider.clone(),
                                did_method_provider.clone(),
                                data_repository.get_validity_credential_repository(),
                                key_provider.clone(),
                                client.clone(),
                                params,
                            ))
                        }) as _
                    }
                    RevocationType::TokenStatusList => {
                        let params = config
                            .get(key)
                            .expect("failed to get TokenStatusList params");

                        Arc::new(
                            TokenStatusList::new(
                                Some(core_base_url.clone()),
                                key_algorithm_provider.clone(),
                                did_method_provider.clone(),
                                key_provider.clone(),
                                initialize_statuslist_loader(
                                    &cache_entities_config,
                                    data_repository.clone(),
                                ),
                                formatter_provider.clone(),
                                client.clone(),
                                Some(params),
                            )
                            .expect("failed to create TokenStatusList revocation"),
                        ) as _
                    }
                };

                revocation_methods.insert(key.to_string(), revocation_method);
            }

            for (key, value) in config.iter_mut() {
                if let Some(entity) = revocation_methods.get(key) {
                    value.capabilities = Some(json!(entity.get_capabilities()));
                }
            }

            // we keep `STATUSLIST2021` only for validation
            revocation_methods.insert(
                "STATUSLIST2021".to_string(),
                Arc::new(StatusList2021 {
                    key_algorithm_provider: key_algorithm_provider.clone(),
                    did_method_provider: did_method_provider.clone(),
                    client,
                }) as _,
            );

            Arc::new(RevocationMethodProviderImpl::new(revocation_methods))
        })
    };

    OneCoreBuilder::new(app_config.core.clone())
        .with_base_url(app_config.app.core_base_url.to_owned())
        .with_crypto(crypto)
        .with_jsonld_caching_loader(caching_loader)
        .with_data_provider_creator(storage_creator)
        .with_key_algorithm_provider(key_algo_creator)
        .with_key_storage_provider(key_storage_creator)
        .with_did_method_provider(did_method_creator)
        .with_formatter_provider(formatter_provider_creator)
        .with_revocation_method_provider(revocation_method_creator)
        .with_vct_type_metadata_cache(vct_type_metadata_cache)
        .with_json_schema_cache(json_schema_cache)
        .with_trust_listcache(trust_list_cache)
        .with_client(client)
        .with_mqtt_client(Arc::new(RumqttcClient::default()))
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
                traces_sample_rate: 0.01,
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

pub fn initialize_did_caching_loader(
    cache_entities_config: &CacheEntitiesConfig,
    data_provider: Arc<dyn DataRepository>,
) -> DidCachingLoader {
    let config = cache_entities_config
        .entities
        .get("DID_DOCUMENT")
        .cloned()
        .unwrap_or(CacheEntityConfig {
            cache_refresh_timeout: Duration::days(1),
            cache_size: 100,
            cache_type: CacheEntityCacheType::Db,
            refresh_after: Duration::minutes(5),
        });

    let storage: Arc<dyn RemoteEntityStorage> = match config.cache_type {
        CacheEntityCacheType::Db => Arc::new(DbStorage::new(
            data_provider.get_remote_entity_cache_repository(),
        )),
        CacheEntityCacheType::InMemory => Arc::new(InMemoryStorage::new(HashMap::new())),
    };

    DidCachingLoader::new(
        RemoteEntityType::DidDocument,
        storage,
        config.cache_size as usize,
        config.cache_refresh_timeout,
        config.refresh_after,
    )
}

pub fn initialize_jsonld_cache_loader(
    cache_entities_config: &CacheEntitiesConfig,
    data_provider: Arc<dyn DataRepository>,
) -> JsonLdCachingLoader {
    let config = cache_entities_config
        .entities
        .get("JSON_LD_CONTEXT")
        .cloned()
        .unwrap_or(CacheEntityConfig {
            cache_refresh_timeout: Duration::days(1),
            cache_size: 100,
            cache_type: CacheEntityCacheType::Db,
            refresh_after: Duration::minutes(5),
        });

    let storage: Arc<dyn RemoteEntityStorage> = match config.cache_type {
        CacheEntityCacheType::Db => Arc::new(DbStorage::new(
            data_provider.get_remote_entity_cache_repository(),
        )),
        CacheEntityCacheType::InMemory => Arc::new(InMemoryStorage::new(Default::default())),
    };

    JsonLdCachingLoader::new(
        RemoteEntityType::JsonLdContext,
        storage,
        config.cache_size as usize,
        config.cache_refresh_timeout,
        config.refresh_after,
    )
}

pub fn initialize_statuslist_loader(
    cache_entities_config: &CacheEntitiesConfig,
    data_provider: Arc<dyn DataRepository>,
) -> StatusListCachingLoader {
    let config = cache_entities_config
        .entities
        .get("STATUS_LIST_CREDENTIAL")
        .cloned()
        .unwrap_or(CacheEntityConfig {
            cache_refresh_timeout: Duration::days(1),
            cache_size: 100,
            cache_type: CacheEntityCacheType::Db,
            refresh_after: Duration::minutes(5),
        });

    let storage: Arc<dyn RemoteEntityStorage> = match config.cache_type {
        CacheEntityCacheType::Db => Arc::new(DbStorage::new(
            data_provider.get_remote_entity_cache_repository(),
        )),
        CacheEntityCacheType::InMemory => Arc::new(InMemoryStorage::new(HashMap::new())),
    };

    StatusListCachingLoader::new(
        RemoteEntityType::StatusListCredential,
        storage,
        config.cache_size as usize,
        config.cache_refresh_timeout,
        config.refresh_after,
    )
}

pub async fn initialize_vct_type_metadata_cache(
    cache_entities_config: &CacheEntitiesConfig,
    repo: Arc<dyn RemoteEntityCacheRepository>,
    client: Arc<dyn HttpClient>,
) -> VctTypeMetadataCache {
    let config = cache_entities_config
        .entities
        .get("VCT_METADATA")
        .cloned()
        .unwrap_or(CacheEntityConfig {
            cache_refresh_timeout: Duration::days(1),
            cache_size: 100,
            cache_type: CacheEntityCacheType::Db,
            refresh_after: Duration::minutes(5),
        });

    let storage: Arc<dyn RemoteEntityStorage> = match config.cache_type {
        CacheEntityCacheType::Db => Arc::new(DbStorage::new(repo)),
        CacheEntityCacheType::InMemory => Arc::new(InMemoryStorage::new(HashMap::new())),
    };

    let cache = VctTypeMetadataCache::new(
        Arc::new(VctTypeMetadataResolver::new(client)),
        storage,
        config.cache_size as usize,
        config.cache_refresh_timeout,
        config.refresh_after,
    );

    cache
        .initialize_from_static_resources()
        .await
        .expect("Failed initializing VCT type metadata cache");

    cache
}

pub async fn initialize_json_schema_loader(
    cache_entities_config: &CacheEntitiesConfig,
    repo: Arc<dyn RemoteEntityCacheRepository>,
    client: Arc<dyn HttpClient>,
) -> JsonSchemaCache {
    let config = cache_entities_config
        .entities
        .get("JSON_SCHEMA")
        .cloned()
        .unwrap_or(CacheEntityConfig {
            cache_refresh_timeout: Duration::days(1),
            cache_size: 100,
            cache_type: CacheEntityCacheType::Db,
            refresh_after: Duration::minutes(5),
        });

    let storage: Arc<dyn RemoteEntityStorage> = match config.cache_type {
        CacheEntityCacheType::Db => Arc::new(DbStorage::new(repo)),
        CacheEntityCacheType::InMemory => Arc::new(InMemoryStorage::new(HashMap::new())),
    };

    let cache = JsonSchemaCache::new(
        Arc::new(JsonSchemaResolver::new(client)),
        storage,
        config.cache_size as usize,
        config.cache_refresh_timeout,
        config.refresh_after,
    );

    cache
        .initialize_from_static_resources()
        .await
        .expect("Failed initializing JSON schema cache");

    cache
}

pub async fn initialize_trust_list_cache(
    cache_entities_config: &CacheEntitiesConfig,
    repo: Arc<dyn RemoteEntityCacheRepository>,
    client: Arc<dyn HttpClient>,
) -> TrustListCache {
    let config = cache_entities_config
        .entities
        .get("TRUST_LIST")
        .cloned()
        .unwrap_or(CacheEntityConfig {
            cache_refresh_timeout: Duration::days(1),
            cache_size: 100,
            cache_type: CacheEntityCacheType::Db,
            refresh_after: Duration::minutes(5),
        });

    let storage: Arc<dyn RemoteEntityStorage> = match config.cache_type {
        CacheEntityCacheType::Db => Arc::new(DbStorage::new(repo)),
        CacheEntityCacheType::InMemory => Arc::new(InMemoryStorage::new(HashMap::new())),
    };

    TrustListCache::new(
        Arc::new(TrustListResolver::new(client)),
        storage,
        config.cache_size as usize,
        config.cache_refresh_timeout,
        config.refresh_after,
    )
}
