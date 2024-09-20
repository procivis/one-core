#![cfg_attr(feature = "strict", deny(warnings))]

use std::collections::HashMap;
use std::sync::Arc;

use error::{BindingError, BleErrorWrapper, NativeKeyStorageError};
use one_core::config::core_config::{self, AppConfig, CacheEntityCacheType, CacheEntityConfig};
use one_core::config::{ConfigError, ConfigParsingError, ConfigValidationError};
use one_core::provider::bluetooth_low_energy::BleError;
use one_core::provider::credential_formatter::json_ld_classic::JsonLdClassic;
use one_core::provider::credential_formatter::mdoc_formatter::MdocFormatter;
use one_core::provider::credential_formatter::physical_card::PhysicalCardFormatter;
use one_core::provider::credential_formatter::FormatterCapabilities;
use one_core::provider::did_method::mdl::{DidMdl, DidMdlValidator};
use one_core::provider::did_method::x509::X509Method;
use one_core::provider::key_algorithm::ml_dsa::MlDsa;
use one_core::provider::key_storage::secure_element::SecureElementKeyProvider;
use one_core::provider::key_storage::KeyStorageCapabilities;
use one_core::repository::DataRepository;
use one_core::{
    DataProviderCreator, DidMethodCreator, FormatterProviderCreator, KeyAlgorithmCreator,
    KeyStorageCreator, OneCoreBuilder, RevocationMethodCreator,
};
use one_crypto::imp::hasher::sha256::SHA256;
use one_crypto::imp::signer::bbs::BBSSigner;
use one_crypto::imp::signer::crydi3::CRYDI3Signer;
use one_crypto::imp::signer::eddsa::EDDSASigner;
use one_crypto::imp::signer::es256::ES256Signer;
use one_crypto::imp::CryptoProviderImpl;
use one_crypto::{Hasher, Signer};
use one_providers::credential_formatter::imp::json_ld::context::caching_loader::JsonLdCachingLoader;
use one_providers::credential_formatter::imp::json_ld_bbsplus::JsonLdBbsplus;
use one_providers::credential_formatter::imp::jwt_formatter::JWTFormatter;
use one_providers::credential_formatter::imp::provider::CredentialFormatterProviderImpl;
use one_providers::credential_formatter::imp::sdjwt_formatter::SDJWTFormatter;
use one_providers::credential_formatter::CredentialFormatter;
use one_providers::did::imp::jwk::JWKDidMethod;
use one_providers::did::imp::key::KeyDidMethod;
use one_providers::did::imp::provider::DidMethodProviderImpl;
use one_providers::did::imp::resolver::DidCachingLoader;
use one_providers::did::imp::universal::UniversalDidMethod;
use one_providers::did::imp::web::WebDidMethod;
use one_providers::did::DidMethod;
use one_providers::http_client::imp::reqwest_client::ReqwestClient;
use one_providers::http_client::HttpClient;
use one_providers::key_algorithm::imp::bbs::BBS;
use one_providers::key_algorithm::imp::eddsa::Eddsa;
use one_providers::key_algorithm::imp::es256::Es256;
use one_providers::key_algorithm::imp::provider::KeyAlgorithmProviderImpl;
use one_providers::key_algorithm::KeyAlgorithm;
use one_providers::key_storage::imp::internal::InternalKeyProvider;
use one_providers::key_storage::imp::provider::KeyProviderImpl;
use one_providers::key_storage::KeyStorage;
use one_providers::remote_entity_storage::in_memory::InMemoryStorage;
use one_providers::remote_entity_storage::{RemoteEntityStorage, RemoteEntityType};
use one_providers::revocation::imp::bitstring_status_list::resolver::StatusListCachingLoader;
use one_providers::revocation::imp::bitstring_status_list::BitstringStatusList;
use one_providers::revocation::imp::lvvc::LvvcProvider;
use one_providers::revocation::imp::provider::RevocationMethodProviderImpl;
use one_providers::revocation::RevocationMethod;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sql_data_provider::DataLayer;
use time::Duration;
use utils::native_ble_central::BleCentralWrapper;
use utils::native_ble_peripheral::BlePeripheralWrapper;
use utils::native_key_storage::NativeKeyStorageWrapper;

use crate::did_config::{DidMdlParams, DidUniversalParams, DidWebParams};

mod binding;
mod did_config;
mod dto;
mod error;
mod functions;
mod mapper;
mod utils;

use binding::OneCoreBinding;
use dto::*;
use one_core::config::core_config::{CacheEntitiesConfig, RevocationType};
use one_core::provider::remote_entity_storage::db_storage::DbStorage;
use one_core::provider::revocation::none::NoneRevocation;
use one_core::provider::revocation::status_list_2021::StatusList2021;

uniffi::include_scaffolding!("one_core");

fn initialize_core(
    data_dir_path: String,
    config_mobile: &'static str,
    native_key_storage: Option<Box<dyn dto::NativeKeyStorage>>,
    ble_central: Option<Arc<dyn BleCentral>>,
    ble_peripheral: Option<Arc<dyn BlePeripheral>>,
) -> Result<Arc<OneCoreBinding>, BindingError> {
    #[cfg(target_os = "android")]
    {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        _ = tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::new(
                "info,sea_orm=warn,sqlx::query=error",
            ))
            .with(tracing_android::layer("ProcivisOneCore").unwrap())
            .try_init();
    }

    let native_key_storage: Option<
        Arc<dyn one_core::provider::key_storage::secure_element::NativeKeyStorage>,
    > = native_key_storage.map(|storage| Arc::new(NativeKeyStorageWrapper(storage)) as _);

    let ble_central = ble_central.map(|central| Arc::new(BleCentralWrapper(central)) as _);
    let ble_peripheral =
        ble_peripheral.map(|peripheral| Arc::new(BlePeripheralWrapper(peripheral)) as _);

    let config = include_str!("../../../config/config.yml");
    let config_base = include_str!("../../../config/config-procivis-base.yml");

    let placeholder_config: AppConfig<MobileConfig> =
        core_config::AppConfig::from_yaml_str_configs(vec![config, config_base, config_mobile])?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| BindingError::Unknown(e.to_string()))?;

    let main_db_path = format!("{data_dir_path}/one_core_db.sqlite");
    let backup_db_path = format!("{data_dir_path}/backup_one_core_db.sqlite");
    let _ = std::fs::remove_file(&backup_db_path);

    let core_builder = move |db_path: String| {
        let core_config = placeholder_config.core.clone();

        let native_key_storage = native_key_storage.clone();
        let ble_peripheral = ble_peripheral.clone();
        let ble_central = ble_central.clone();

        Box::pin(async move {
            let db_url = format!("sqlite:{db_path}?mode=rwc");
            let db_conn = sql_data_provider::db_conn(db_url, true)
                .await
                .map_err(|e| BindingError::DbErr(e.to_string()))?;

            let hashers: Vec<(String, Arc<dyn Hasher>)> =
                vec![("sha-256".to_string(), Arc::new(SHA256 {}))];

            let signers: Vec<(String, Arc<dyn Signer>)> = vec![
                ("Ed25519".to_string(), Arc::new(EDDSASigner {})),
                ("ES256".to_string(), Arc::new(ES256Signer {})),
                ("CRYDI3".to_string(), Arc::new(CRYDI3Signer {})),
                ("BBS".to_string(), Arc::new(BBSSigner {})),
            ];

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
                        .expect("Crypto is required to start")
                        .clone(),
                ))
            });

            let key_storage_creator: KeyStorageCreator = Box::new(move |config, providers| {
                let mut key_providers: HashMap<String, Arc<dyn KeyStorage>> = HashMap::new();

                for (name, field) in config.iter() {
                    let provider = match (field.r#type.as_str(), field.disabled()) {
                        ("SECURE_ELEMENT", false) => {
                            let local_native_key_storage: Arc<dyn one_core::provider::key_storage::secure_element::NativeKeyStorage> =
                                native_key_storage.clone().expect("Missing native key provider");
                            let params =
                                config.get(name).expect("Secure element config is required");
                            Some(Arc::new(SecureElementKeyProvider::new(
                                local_native_key_storage.clone(),
                                params,
                            )) as _)
                        }
                        ("INTERNAL", false) => {
                            let params = config
                                .get(name)
                                .expect("Internal key provider config is required");
                            Some(Arc::new(InternalKeyProvider::new(
                                providers
                                    .key_algorithm_provider
                                    .as_ref()
                                    .expect("Missing key algorithm provider")
                                    .clone(),
                                params,
                            )) as _)
                        }
                        (other, false) => panic!("Unexpected key storage: {other}"),
                        (_, true) => None,
                    };

                    if let Some(provider) = provider {
                        key_providers.insert(name.to_owned(), provider);
                    };
                }

                for (key, value) in config.iter_mut() {
                    if let Some(entity) = key_providers.get(key) {
                        value.capabilities = Some(json!(Into::<KeyStorageCapabilities>::into(
                            entity.get_capabilities()
                        )));
                    }
                }

                Arc::new(KeyProviderImpl::new(key_providers.to_owned()))
            });

            let data_repository = Arc::new(DataLayer::build(db_conn, vec!["INTERNAL".to_string()]));

            let storage_creator: DataProviderCreator = {
                let data_repository = data_repository.clone();
                Box::new(move || data_repository)
            };

            let cache_entities_config = core_config.cache_entities.to_owned();
            let reqwest_client = reqwest::Client::builder()
                .https_only(!placeholder_config.app.allow_insecure_http_transport)
                .build()
                .expect("Failed to create reqwest::Client");

            let client: Arc<dyn HttpClient> = Arc::new(ReqwestClient::new(reqwest_client));
            let data_provider = data_repository.clone();
            let did_method_creator: DidMethodCreator = {
                let client = client.clone();
                Box::new(move |config, providers| {
                    let mut did_mdl_validator: Option<Arc<dyn DidMdlValidator>> = None;

                    let mut did_methods: HashMap<String, Arc<dyn DidMethod>> = HashMap::new();

                    for (name, field) in config.iter() {
                        let did_method: Arc<dyn DidMethod> = match field.r#type.to_string().as_str()
                        {
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
                                    &providers.core_base_url,
                                    client.clone(),
                                    params.into(),
                                )
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
                                Arc::new(UniversalDidMethod::new(params.into(), client.clone()))
                                    as _
                            }
                            "MDL" => {
                                let key_algorithm_provider = providers
                                    .key_algorithm_provider
                                    .to_owned()
                                    .expect("key algorithm provider is required");

                                let params: DidMdlParams = config
                                    .get(name)
                                    .expect("failed to deserialize did mdl params");

                                let did_mdl =
                                    DidMdl::new(params.into(), key_algorithm_provider.clone())
                                        .map_err(|err| {
                                            ConfigParsingError::GeneralParsingError(format!(
                                                "Invalid DID MDL config: {err}"
                                            ))
                                        })
                                        .expect("failed to create did mdl method");
                                let did_mdl = Arc::new(did_mdl);

                                did_mdl_validator =
                                    Some(did_mdl.clone() as Arc<dyn DidMdlValidator>);

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
                            let capabilities: did_config::DidCapabilities =
                                entity.get_capabilities().into();

                            *value = core_config::Fields {
                                capabilities: Some(json!(capabilities)),
                                params,
                                ..value.clone()
                            }
                        }
                    }

                    let did_caching_loader =
                        initialize_did_caching_loader(&cache_entities_config, data_provider);

                    (
                        Arc::new(DidMethodProviderImpl::new(did_caching_loader, did_methods)),
                        did_mdl_validator,
                    )
                })
            };

            let caching_loader = initialize_jsonld_cache_loader(
                core_config.cache_entities.to_owned(),
                data_repository.to_owned(),
            );

            let formatter_provider_creator: FormatterProviderCreator = {
                let caching_loader = caching_loader.clone();
                let client = client.clone();
                Box::new(move |format_config, datatype_config, providers| {
                    let mut formatters: HashMap<String, Arc<dyn CredentialFormatter>> =
                        HashMap::new();

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
                            "SDJWT" => {
                                let params = format_config
                                    .get(name)
                                    .expect("SDJWT formatter params are mandatory");
                                Arc::new(SDJWTFormatter::new(params, crypto.clone())) as _
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
                            _ => unimplemented!(),
                        };
                        formatters.insert(name.to_owned(), formatter);
                    }

                    for (key, value) in format_config.iter_mut() {
                        if let Some(entity) = formatters.get(key) {
                            value.capabilities = Some(json!(Into::<FormatterCapabilities>::into(
                                entity.get_capabilities()
                            )));
                        }
                    }

                    Arc::new(CredentialFormatterProviderImpl::new(formatters))
                })
            };

            let cache_entities_config = core_config.cache_entities.to_owned();
            let revocation_method_creator: RevocationMethodCreator = {
                let client = client.clone();
                Box::new(move |config, providers| {
                    let mut revocation_methods: HashMap<String, Arc<dyn RevocationMethod>> =
                        HashMap::new();

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
                            RevocationType::BitstringStatusList => {
                                Arc::new(BitstringStatusList::new(
                                    None,
                                    key_algorithm_provider.clone(),
                                    did_method_provider.clone(),
                                    key_provider.clone(),
                                    formatter_provider.clone(),
                                    initialize_statuslist_loader(
                                        &cache_entities_config,
                                        data_repository.clone(),
                                    ),
                                    client.clone(),
                                    None,
                                )) as _
                            }
                            RevocationType::Lvvc => {
                                ({
                                    let params =
                                        config.get(key).expect("failed to get LVVC params");
                                    Arc::new(LvvcProvider::new(
                                        None,
                                        formatter_provider.clone(),
                                        did_method_provider.clone(),
                                        key_provider.clone(),
                                        client.clone(),
                                        params,
                                    ))
                                }) as _
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

            OneCoreBuilder::new(core_config.clone())
                .with_crypto(crypto)
                .with_jsonld_caching_loader(caching_loader)
                .with_data_provider_creator(storage_creator)
                .with_key_algorithm_provider(key_algo_creator)
                .with_key_storage_provider(key_storage_creator)
                .with_did_method_provider(did_method_creator)
                .with_formatter_provider(formatter_provider_creator)
                .with_ble(ble_peripheral, ble_central)
                .with_revocation_method_provider(revocation_method_creator)
                .with_client(client)
                .build()
                .map_err(|e| BindingError::DbErr(e.to_string()))
        }) as _
    };

    let core_binding = Arc::new(OneCoreBinding::new(
        runtime,
        main_db_path,
        backup_db_path,
        Box::new(core_builder),
    ));

    core_binding.initialize(core_binding.main_db_path.clone())?;

    Ok(core_binding)
}

fn initialize_verifier_core(
    data_dir_path: String,
    native_key_storage: Option<Box<dyn NativeKeyStorage>>,
    ble_central: Option<Arc<dyn BleCentral>>,
    ble_peripheral: Option<Arc<dyn BlePeripheral>>,
) -> Result<Arc<OneCoreBinding>, BindingError> {
    initialize_core(
        data_dir_path,
        include_str!("../../../config/config-procivis-mobile-verifier.yml"),
        native_key_storage,
        ble_central,
        ble_peripheral,
    )
}

fn initialize_holder_core(
    data_dir_path: String,
    native_key_storage: Option<Box<dyn NativeKeyStorage>>,
    ble_central: Option<Arc<dyn BleCentral>>,
    ble_peripheral: Option<Arc<dyn BlePeripheral>>,
) -> Result<Arc<OneCoreBinding>, BindingError> {
    initialize_core(
        data_dir_path,
        include_str!("../../../config/config-procivis-mobile-holder.yml"),
        native_key_storage,
        ble_central,
        ble_peripheral,
    )
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct MobileConfig {
    pub allow_insecure_http_transport: bool,
}

pub fn initialize_jsonld_cache_loader(
    cache_entities_config: CacheEntitiesConfig,
    data_provider: Arc<dyn DataRepository>,
) -> JsonLdCachingLoader {
    let json_ld_context_config = cache_entities_config
        .entities
        .get("JSON_LD_CONTEXT")
        .cloned()
        .unwrap_or(CacheEntityConfig {
            cache_refresh_timeout: Duration::days(1),
            cache_size: 100,
            cache_type: CacheEntityCacheType::Db,
            refresh_after: Duration::minutes(5),
        });

    let remote_entity_storage: Arc<dyn RemoteEntityStorage> =
        match json_ld_context_config.cache_type {
            CacheEntityCacheType::Db => Arc::new(DbStorage::new(
                data_provider.get_remote_entity_cache_repository(),
            )),
            CacheEntityCacheType::InMemory => Arc::new(InMemoryStorage::new(Default::default())),
        };
    JsonLdCachingLoader::new(
        RemoteEntityType::JsonLdContext,
        remote_entity_storage,
        json_ld_context_config.cache_size as usize,
        json_ld_context_config.cache_refresh_timeout,
        json_ld_context_config.refresh_after,
    )
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
