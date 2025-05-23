#![cfg_attr(feature = "strict", deny(warnings))]

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use did_config::DidWebVhParams;
use indexmap::IndexMap;
use one_core::config::core_config::{
    self, AppConfig, CacheEntitiesConfig, CacheEntityCacheType, CacheEntityConfig, DidType,
    FormatType, InputFormat, KeyAlgorithmType, KeyStorageType, RevocationType,
};
use one_core::config::{ConfigError, ConfigParsingError, ConfigValidationError};
use one_core::provider::caching_loader::json_schema::{JsonSchemaCache, JsonSchemaResolver};
use one_core::provider::caching_loader::trust_list::{TrustListCache, TrustListResolver};
use one_core::provider::caching_loader::vct::{VctTypeMetadataCache, VctTypeMetadataResolver};
use one_core::provider::credential_formatter::CredentialFormatter;
use one_core::provider::credential_formatter::json_ld::context::caching_loader::JsonLdCachingLoader;
use one_core::provider::credential_formatter::json_ld_bbsplus::JsonLdBbsplus;
use one_core::provider::credential_formatter::json_ld_classic::JsonLdClassic;
use one_core::provider::credential_formatter::jwt_formatter::JWTFormatter;
use one_core::provider::credential_formatter::mdoc_formatter::MdocFormatter;
use one_core::provider::credential_formatter::physical_card::PhysicalCardFormatter;
use one_core::provider::credential_formatter::provider::CredentialFormatterProviderImpl;
use one_core::provider::credential_formatter::sdjwt_formatter::SDJWTFormatter;
use one_core::provider::credential_formatter::sdjwtvc_formatter::SDJWTVCFormatter;
use one_core::provider::did_method::DidMethod;
use one_core::provider::did_method::jwk::JWKDidMethod;
use one_core::provider::did_method::key::KeyDidMethod;
use one_core::provider::did_method::mdl::{DidMdl, DidMdlValidator};
use one_core::provider::did_method::provider::DidMethodProviderImpl;
use one_core::provider::did_method::resolver::DidCachingLoader;
use one_core::provider::did_method::sd_jwt_vc_issuer_metadata::SdJwtVcIssuerMetadataDidMethod;
use one_core::provider::did_method::universal::UniversalDidMethod;
use one_core::provider::did_method::web::WebDidMethod;
use one_core::provider::did_method::webvh::DidWebVh;
use one_core::provider::did_method::x509::X509Method;
use one_core::provider::http_client::HttpClient;
use one_core::provider::http_client::reqwest_client::ReqwestClient;
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::bbs::BBS;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use one_core::provider::key_algorithm::eddsa::Eddsa;
use one_core::provider::key_algorithm::ml_dsa::MlDsa;
use one_core::provider::key_algorithm::provider::KeyAlgorithmProviderImpl;
use one_core::provider::key_storage::KeyStorage;
use one_core::provider::key_storage::internal::InternalKeyProvider;
use one_core::provider::key_storage::provider::KeyProviderImpl;
use one_core::provider::key_storage::remote_secure_element::RemoteSecureElementKeyProvider;
use one_core::provider::key_storage::secure_element::SecureElementKeyProvider;
use one_core::provider::mqtt_client::rumqttc_client::RumqttcClient;
use one_core::provider::remote_entity_storage::db_storage::DbStorage;
use one_core::provider::remote_entity_storage::in_memory::InMemoryStorage;
use one_core::provider::remote_entity_storage::{RemoteEntityStorage, RemoteEntityType};
use one_core::provider::revocation::RevocationMethod;
use one_core::provider::revocation::bitstring_status_list::BitstringStatusList;
use one_core::provider::revocation::bitstring_status_list::resolver::StatusListCachingLoader;
use one_core::provider::revocation::lvvc::LvvcProvider;
use one_core::provider::revocation::mdoc_mso_update_suspension::MdocMsoUpdateSuspensionRevocation;
use one_core::provider::revocation::none::NoneRevocation;
use one_core::provider::revocation::provider::RevocationMethodProviderImpl;
use one_core::provider::revocation::status_list_2021::StatusList2021;
use one_core::provider::revocation::token_status_list::TokenStatusList;
use one_core::repository::DataRepository;
use one_core::repository::error::DataLayerError;
use one_core::repository::remote_entity_cache_repository::RemoteEntityCacheRepository;
use one_core::service::error::ServiceError;
use one_core::{
    DataProviderCreator, DidMethodCreator, FormatterProviderCreator, KeyAlgorithmCreator,
    KeyStorageCreator, OneCoreBuilder, RevocationMethodCreator,
};
use one_crypto::hasher::sha256::SHA256;
use one_crypto::signer::bbs::BBSSigner;
use one_crypto::signer::crydi3::CRYDI3Signer;
use one_crypto::signer::ecdsa::ECDSASigner;
use one_crypto::signer::eddsa::EDDSASigner;
use one_crypto::{CryptoProviderImpl, Hasher, Signer};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sql_data_provider::DataLayer;
use time::Duration;
use tracing::warn;

use crate::binding::OneCoreBinding;
use crate::binding::ble::{BleCentral, BleCentralWrapper, BlePeripheral, BlePeripheralWrapper};
use crate::binding::key_storage::{NativeKeyStorage, NativeKeyStorageWrapper};
use crate::did_config::{
    DidMdlParams, DidSdJwtVCIssuerMetadataParams, DidUniversalParams, DidWebParams,
};
use crate::error::{BindingError, SDKError};

mod binding;
mod did_config;
mod error;
mod error_code;
mod utils;

uniffi::setup_scaffolding!();

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
struct MobileConfig {
    pub allow_insecure_http_transport: bool,
    pub trace_level: Option<String>,
}

#[uniffi::export]
fn initialize_core(
    config_json: String,
    data_dir_path: String,
    native_secure_element: Option<Arc<dyn NativeKeyStorage>>,
    remote_secure_element: Option<Arc<dyn NativeKeyStorage>>,
    ble_central: Option<Arc<dyn BleCentral>>,
    ble_peripheral: Option<Arc<dyn BlePeripheral>>,
) -> Result<Arc<OneCoreBinding>, BindingError> {
    // Sets tokio as global runtime for all async exports
    static TOKIO_RUNTIME: LazyLock<Result<tokio::runtime::Runtime, std::io::Error>> =
        LazyLock::new(|| {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;

            runtime.block_on(uniffi::deps::async_compat::Compat::new(async {}));
            Ok(runtime)
        });
    let rt = TOKIO_RUNTIME
        .as_ref()
        .map_err(|err| BindingError::from(SDKError::InitializationFailure(err.to_string())))?;

    rt.block_on(initialize(
        config_json,
        data_dir_path,
        native_secure_element,
        remote_secure_element,
        ble_central,
        ble_peripheral,
    ))
}

async fn initialize(
    config_json: String,
    data_dir_path: String,
    native_secure_element: Option<Arc<dyn NativeKeyStorage>>,
    remote_secure_element: Option<Arc<dyn NativeKeyStorage>>,
    ble_central: Option<Arc<dyn BleCentral>>,
    ble_peripheral: Option<Arc<dyn BlePeripheral>>,
) -> Result<Arc<OneCoreBinding>, BindingError> {
    let native_secure_element: Option<
        Arc<dyn one_core::provider::key_storage::secure_element::NativeKeyStorage>,
    > = native_secure_element.map(|storage| Arc::new(NativeKeyStorageWrapper(storage)) as _);

    let remote_secure_element: Option<
        Arc<dyn one_core::provider::key_storage::secure_element::NativeKeyStorage>,
    > = remote_secure_element.map(|storage| Arc::new(NativeKeyStorageWrapper(storage)) as _);

    let ble_central = ble_central.map(|central| Arc::new(BleCentralWrapper(central)) as _);
    let ble_peripheral =
        ble_peripheral.map(|peripheral| Arc::new(BlePeripheralWrapper(peripheral)) as _);

    let cfg = build_config(&config_json)?;

    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        let default_trace_level = "info,sea_orm=warn,sqlx::query=error".to_string();
        let trace_level = cfg.app.trace_level.as_ref().unwrap_or(&default_trace_level);

        let subscriber =
            tracing_subscriber::registry().with(tracing_subscriber::EnvFilter::new(trace_level));

        #[cfg(target_os = "android")]
        let subscriber = subscriber.with(
            tracing_android::layer("ProcivisOneCore")
                .expect("Failed to create tracing_android layer"),
        );

        #[cfg(target_os = "ios")]
        let subscriber =
            subscriber.with(tracing_oslog::OsLogger::new("ProcivisOneCore", "default"));

        #[allow(unused_must_use)]
        subscriber.try_init();
    }

    let main_db_path = format!("{data_dir_path}/one_core_db.sqlite");
    let backup_db_path = format!("{data_dir_path}/backup_one_core_db.sqlite");
    let result = std::fs::remove_file(&backup_db_path);
    if let Err(err) = result {
        warn!("failed to delete backup database: {err}");
    }

    let core_builder = move |db_path: String| {
        let core_config = cfg.core.clone();

        let native_secure_element = native_secure_element.clone();
        let remote_secure_element = remote_secure_element.clone();
        let ble_peripheral = ble_peripheral.clone();
        let ble_central = ble_central.clone();

        Box::pin(async move {
            let db_url = format!("sqlite:{db_path}?mode=rwc");
            let db_conn = sql_data_provider::db_conn(db_url, true)
                .await
                .map_err(|e| ServiceError::Repository(DataLayerError::Db(e.into())))?;

            let hashers: Vec<(String, Arc<dyn Hasher>)> =
                vec![("sha-256".to_string(), Arc::new(SHA256 {}))];

            let signers: Vec<(String, Arc<dyn Signer>)> = vec![
                ("Ed25519".to_string(), Arc::new(EDDSASigner {})),
                ("ECDSA".to_string(), Arc::new(ECDSASigner {})),
                ("CRYDI3".to_string(), Arc::new(CRYDI3Signer {})),
                ("BBS".to_string(), Arc::new(BBSSigner {})),
            ];

            let crypto = Arc::new(CryptoProviderImpl::new(
                HashMap::from_iter(hashers),
                HashMap::from_iter(signers),
            ));

            let key_algo_creator: KeyAlgorithmCreator = Box::new(|config, _| {
                let mut key_algorithms: HashMap<KeyAlgorithmType, Arc<dyn KeyAlgorithm>> =
                    HashMap::new();

                for (name, fields) in config.iter() {
                    if fields.enabled.is_some_and(|value| !value) {
                        continue;
                    }
                    let key_algorithm: Arc<dyn KeyAlgorithm> = match name {
                        KeyAlgorithmType::Eddsa => Arc::new(Eddsa),
                        KeyAlgorithmType::Ecdsa => Arc::new(Ecdsa),
                        KeyAlgorithmType::BbsPlus => Arc::new(BBS),
                        KeyAlgorithmType::Dilithium => Arc::new(MlDsa),
                    };
                    key_algorithms.insert(name.to_owned(), key_algorithm);
                }

                Arc::new(KeyAlgorithmProviderImpl::new(key_algorithms))
            });

            let key_storage_creator: KeyStorageCreator = Box::new(move |config, providers| {
                let mut key_providers: HashMap<String, Arc<dyn KeyStorage>> = HashMap::new();

                for (name, field) in config.iter().filter(|(_, field)| field.enabled()) {
                    let provider = match field.r#type {
                        KeyStorageType::SecureElement => {
                            let native_storage = native_secure_element
                                .clone()
                                .expect("Missing native key provider");
                            let params =
                                config.get(name).expect("Secure element config is required");
                            Arc::new(SecureElementKeyProvider::new(native_storage, params)) as _
                        }
                        KeyStorageType::RemoteSecureElement => {
                            let native_storage = remote_secure_element
                                .clone()
                                .expect("Missing native remote key provider");
                            Arc::new(RemoteSecureElementKeyProvider::new(native_storage)) as _
                        }
                        KeyStorageType::Internal => {
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
                        _ => {
                            panic!("Unexpected key storage: {name}")
                        }
                    };

                    key_providers.insert(name.to_owned(), provider);
                }

                for (key, value) in config.iter_mut() {
                    if let Some(entity) = key_providers.get(key) {
                        value.capabilities = Some(json!(entity.get_capabilities()));
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
                .https_only(!cfg.app.allow_insecure_http_transport)
                .build()
                .expect("Failed to create reqwest::Client");

            let client: Arc<dyn HttpClient> = Arc::new(ReqwestClient::new(reqwest_client));
            let data_provider = data_repository.clone();
            let did_method_creator: DidMethodCreator = {
                let client = client.clone();
                Box::new(move |config, providers| {
                    let mut did_configs = config.iter().collect::<Vec<_>>();
                    // sort by `order`
                    did_configs
                        .sort_by(|(_, fields1), (_, fields2)| fields1.order.cmp(&fields2.order));
                    let mut did_mdl_validator: Option<Arc<dyn DidMdlValidator>> = None;
                    let mut did_methods: IndexMap<String, Arc<dyn DidMethod>> = IndexMap::new();
                    let mut did_webvh_params: Vec<(String, DidWebVhParams)> = vec![];

                    for (name, field) in did_configs {
                        let did_method: Arc<dyn DidMethod> = match field.r#type {
                            DidType::Key => {
                                let key_algorithm_provider = providers
                                    .key_algorithm_provider
                                    .to_owned()
                                    .expect("key algorithm provider is required");
                                Arc::new(KeyDidMethod::new(key_algorithm_provider.clone())) as _
                            }
                            DidType::Web => {
                                let params: DidWebParams = config
                                    .get(name)
                                    .expect("failed to deserialize did web params");
                                let did_web = WebDidMethod::new(
                                    &providers.core_base_url,
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
                            DidType::Jwk => {
                                let key_algorithm_provider = providers
                                    .key_algorithm_provider
                                    .to_owned()
                                    .expect("key algorithm provider is required");
                                Arc::new(JWKDidMethod::new(key_algorithm_provider.clone())) as _
                            }
                            DidType::X509 => Arc::new(X509Method::new()) as _,
                            DidType::Universal => {
                                let params: DidUniversalParams = config
                                    .get(name)
                                    .expect("failed to deserialize did universal params");
                                Arc::new(UniversalDidMethod::new(params.into(), client.clone()))
                                    as _
                            }
                            DidType::MDL => {
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
                            DidType::SdJwtVcIssuerMetadata => {
                                let key_algorithm_provider = providers
                                    .key_algorithm_provider
                                    .to_owned()
                                    .expect("key algorithm provider is required");

                                let params: DidSdJwtVCIssuerMetadataParams =
                                    config.get(name).expect(
                                        "failed to deserialize did SdJwtVCIssuerMetadata params",
                                    );
                                Arc::new(
                                    SdJwtVcIssuerMetadataDidMethod::new(
                                        client.clone(),
                                        key_algorithm_provider.clone(),
                                        params.into(),
                                    )
                                    .expect("failed to create SdJwtVCIssuerMetadataDidMethod"),
                                )
                            }
                            DidType::WebVh => {
                                let params: DidWebVhParams = config
                                    .get(name)
                                    .expect("failed to deserialize did webvh params");
                                // did:webvh cannot be constructed yet, as it needs a did resolver internally
                                // -> save for later
                                did_webvh_params.push((name.to_string(), params));
                                continue;
                            }
                        };
                        did_methods.insert(name.to_owned(), did_method);
                    }

                    let did_caching_loader = initialize_did_caching_loader(
                        &cache_entities_config,
                        data_provider.clone(),
                    );
                    let intermediary_provider = Arc::new(DidMethodProviderImpl::new(
                        did_caching_loader,
                        did_methods.clone(),
                    ));

                    // Separately construct the did:webvh providers using the intermediary provider
                    for (name, params) in did_webvh_params {
                        let did_webvh = DidWebVh::new(
                            params.into(),
                            providers.core_base_url.clone(),
                            client.clone(),
                            intermediary_provider.clone(),
                            providers.key_storage_provider.clone(),
                        );
                        did_methods.insert(name, Arc::new(did_webvh) as _);
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

                            *value = core_config::Fields {
                                capabilities: Some(json!(entity.get_capabilities())),
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

            let vct_type_metadata_cache = Arc::new(
                initialize_vct_type_metadata_cache(
                    core_config.cache_entities.to_owned(),
                    data_repository.to_owned(),
                    client.clone(),
                )
                .await,
            );

            let json_schema_cache = Arc::new(
                initialize_json_schema_cache(
                    core_config.cache_entities.to_owned(),
                    data_repository.to_owned(),
                    client.clone(),
                )
                .await,
            );

            let trust_list_cache = Arc::new(
                initialize_trust_list_cache(
                    &core_config.cache_entities,
                    data_repository.get_remote_entity_cache_repository().clone(),
                    client.clone(),
                )
                .await,
            );

            let formatter_provider_creator: FormatterProviderCreator = {
                let caching_loader = caching_loader.clone();
                let vct_type_metadata_cache = vct_type_metadata_cache.clone();
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
                        let formatter = match field.r#type {
                            FormatType::Jwt => {
                                let params = format_config
                                    .get(name)
                                    .expect("JWT formatter params are mandatory");
                                Arc::new(JWTFormatter::new(params, key_algorithm_provider.clone()))
                                    as _
                            }
                            FormatType::PhysicalCard => Arc::new(PhysicalCardFormatter::new(
                                crypto.clone(),
                                caching_loader.clone(),
                                client.clone(),
                            )) as _,
                            FormatType::SdJwt => {
                                let params = format_config
                                    .get(name)
                                    .expect("SD-JWT formatter params are mandatory");
                                Arc::new(SDJWTFormatter::new(
                                    params,
                                    crypto.clone(),
                                    did_method_provider.clone(),
                                )) as _
                            }
                            FormatType::SdJwtVc => {
                                let params = format_config
                                    .get(name)
                                    .expect("SD-JWT VC formatter params are mandatory");
                                Arc::new(SDJWTVCFormatter::new(
                                    params,
                                    crypto.clone(),
                                    did_method_provider.clone(),
                                    vct_type_metadata_cache.clone(),
                                )) as _
                            }
                            FormatType::JsonLdClassic => {
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
                            FormatType::JsonLdBbsPlus => {
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
                            FormatType::Mdoc => {
                                let params = format_config
                                    .get(name)
                                    .expect("MDOC formatter params are mandatory");

                                let did_mdl_validator = providers
                                    .did_mdl_validator
                                    .as_ref()
                                    .expect("Did mdl validator is mandatory");

                                Arc::new(MdocFormatter::new(
                                    params,
                                    did_mdl_validator.clone(),
                                    did_method_provider.clone(),
                                    key_algorithm_provider.clone(),
                                    providers.core_base_url.clone(),
                                    datatype_config.clone(),
                                )) as _
                            }
                        };
                        formatters.insert(name.to_owned(), formatter);
                    }

                    for (key, value) in format_config.iter_mut() {
                        if let Some(entity) = formatters.get(key) {
                            value.capabilities = Some(json!(entity.get_capabilities()));
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
                        if !fields.enabled() {
                            continue;
                        }

                        let revocation_method = match fields.r#type {
                            RevocationType::None => Arc::new(NoneRevocation {}) as _,
                            RevocationType::MdocMsoUpdateSuspension => {
                                Arc::new(MdocMsoUpdateSuspensionRevocation {}) as _
                            }
                            RevocationType::BitstringStatusList => {
                                Arc::new(BitstringStatusList::new(
                                    None,
                                    key_algorithm_provider.clone(),
                                    did_method_provider.clone(),
                                    key_provider.clone(),
                                    initialize_statuslist_loader(
                                        &cache_entities_config,
                                        data_repository.clone(),
                                    ),
                                    formatter_provider.clone(),
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
                                        data_repository.get_validity_credential_repository(),
                                        key_provider.clone(),
                                        key_algorithm_provider.clone(),
                                        client.clone(),
                                        params,
                                    ))
                                }) as _
                            }
                            RevocationType::TokenStatusList => Arc::new(
                                TokenStatusList::new(
                                    None,
                                    key_algorithm_provider.clone(),
                                    did_method_provider.clone(),
                                    key_provider.clone(),
                                    initialize_statuslist_loader(
                                        &cache_entities_config,
                                        data_repository.clone(),
                                    ),
                                    formatter_provider.clone(),
                                    client.clone(),
                                    None,
                                )
                                .expect("failed to create TokenStatusList revocation"),
                            ) as _,
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
                .with_mqtt_client(Arc::new(RumqttcClient::default()))
                .with_revocation_method_provider(revocation_method_creator)
                .with_vct_type_metadata_cache(vct_type_metadata_cache)
                .with_json_schema_cache(json_schema_cache)
                .with_client(client)
                .with_trust_listcache(trust_list_cache)
                .build()
                .map_err(|err| SDKError::InitializationFailure(err.to_string()).into())
        }) as _
    };

    let core_binding = Arc::new(OneCoreBinding::new(
        main_db_path,
        backup_db_path,
        Box::new(core_builder),
    ));

    core_binding
        .initialize(core_binding.main_db_path.clone())
        .await?;

    Ok(core_binding)
}

fn initialize_jsonld_cache_loader(
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

fn initialize_did_caching_loader(
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

fn initialize_statuslist_loader(
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

async fn initialize_vct_type_metadata_cache(
    cache_entities_config: CacheEntitiesConfig,
    data_provider: Arc<dyn DataRepository>,
    client: Arc<dyn HttpClient>,
) -> VctTypeMetadataCache {
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

    let remote_entity_storage: Arc<dyn RemoteEntityStorage> = match config.cache_type {
        CacheEntityCacheType::Db => Arc::new(DbStorage::new(
            data_provider.get_remote_entity_cache_repository(),
        )),
        CacheEntityCacheType::InMemory => Arc::new(InMemoryStorage::new(Default::default())),
    };
    let resolver = VctTypeMetadataResolver::new(client);

    let cache = VctTypeMetadataCache::new(
        Arc::new(resolver),
        remote_entity_storage,
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

async fn initialize_json_schema_cache(
    cache_entities_config: CacheEntitiesConfig,
    data_provider: Arc<dyn DataRepository>,
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

    let remote_entity_storage: Arc<dyn RemoteEntityStorage> = match config.cache_type {
        CacheEntityCacheType::Db => Arc::new(DbStorage::new(
            data_provider.get_remote_entity_cache_repository(),
        )),
        CacheEntityCacheType::InMemory => Arc::new(InMemoryStorage::new(Default::default())),
    };
    let resolver = JsonSchemaResolver::new(client);

    let cache = JsonSchemaCache::new(
        Arc::new(resolver),
        remote_entity_storage,
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

async fn initialize_trust_list_cache(
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

fn build_config(config: &str) -> Result<AppConfig<MobileConfig>, SDKError> {
    core_config::AppConfig::parse([
        InputFormat::yaml(include_str!("../../../config/config.yml")),
        InputFormat::yaml(include_str!("../../../config/config-procivis-base.yml")),
        InputFormat::yaml(include_str!("../../../config/config-procivis-mobile.yml")),
        InputFormat::json(config),
    ])
    .map_err(|err| SDKError::InitializationFailure(err.to_string()))
}

#[cfg(test)]
mod test {
    use crate::build_config;

    #[test]
    fn test_build_config_parses_static_configs() {
        assert!(build_config("{}").is_ok());
    }
}
