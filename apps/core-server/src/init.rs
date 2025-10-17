use std::collections::HashMap;
use std::sync::Arc;

use indexmap::IndexMap;
use one_core::config::core_config::{
    AppConfig, CacheEntitiesConfig, CacheEntityCacheType, CacheEntityConfig, ConfigFields, DidType,
    Fields, FormatType, KeyAlgorithmType, KeyStorageType, Params, RevocationType,
};
use one_core::config::{ConfigError, ConfigValidationError, core_config};
use one_core::provider::caching_loader::android_attestation_crl::{
    AndroidAttestationCrlCache, AndroidAttestationCrlResolver,
};
use one_core::provider::caching_loader::json_ld_context::JsonLdCachingLoader;
use one_core::provider::caching_loader::json_schema::{JsonSchemaCache, JsonSchemaResolver};
use one_core::provider::caching_loader::trust_list::{TrustListCache, TrustListResolver};
use one_core::provider::caching_loader::vct::{VctTypeMetadataCache, VctTypeMetadataResolver};
use one_core::provider::caching_loader::x509_crl::{X509CrlCache, X509CrlResolver};
use one_core::provider::credential_formatter::CredentialFormatter;
use one_core::provider::credential_formatter::json_ld_bbsplus::JsonLdBbsplus;
use one_core::provider::credential_formatter::json_ld_classic::JsonLdClassic;
use one_core::provider::credential_formatter::jwt_formatter::JWTFormatter;
use one_core::provider::credential_formatter::mdoc_formatter::MdocFormatter;
use one_core::provider::credential_formatter::physical_card::PhysicalCardFormatter;
use one_core::provider::credential_formatter::provider::CredentialFormatterProviderImpl;
use one_core::provider::credential_formatter::sdjwt_formatter::SDJWTFormatter;
use one_core::provider::credential_formatter::sdjwtvc_formatter::SDJWTVCFormatter;
use one_core::provider::data_type::data_type_provider_from_config;
use one_core::provider::did_method::DidMethod;
use one_core::provider::did_method::jwk::JWKDidMethod;
use one_core::provider::did_method::key::KeyDidMethod;
use one_core::provider::did_method::provider::DidMethodProviderImpl;
use one_core::provider::did_method::resolver::DidCachingLoader;
use one_core::provider::did_method::universal::UniversalDidMethod;
use one_core::provider::did_method::web::WebDidMethod;
use one_core::provider::did_method::webvh::DidWebVh;
use one_core::provider::http_client::HttpClient;
use one_core::provider::http_client::reqwest_client::ReqwestClient;
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::bbs::BBS;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use one_core::provider::key_algorithm::eddsa::Eddsa;
use one_core::provider::key_algorithm::ml_dsa::MlDsa;
use one_core::provider::key_algorithm::model::KeyAlgorithmCapabilities;
use one_core::provider::key_algorithm::provider::KeyAlgorithmProviderImpl;
use one_core::provider::key_storage::KeyStorage;
use one_core::provider::key_storage::azure_vault::AzureVaultKeyProvider;
use one_core::provider::key_storage::internal::InternalKeyProvider;
use one_core::provider::key_storage::pkcs11::PKCS11KeyProvider;
use one_core::provider::key_storage::provider::KeyProviderImpl;
use one_core::provider::mqtt_client::rumqttc_client::RumqttcClient;
use one_core::provider::presentation_formatter::PresentationFormatter;
use one_core::provider::presentation_formatter::jwt_vp_json::JwtVpPresentationFormatter;
use one_core::provider::presentation_formatter::ldp_vp::LdpVpPresentationFormatter;
use one_core::provider::presentation_formatter::mso_mdoc::MsoMdocPresentationFormatter;
use one_core::provider::presentation_formatter::provider::PresentationFormatterProviderImpl;
use one_core::provider::presentation_formatter::sdjwt::SdjwtPresentationFormatter;
use one_core::provider::presentation_formatter::sdjwt_vc::SdjwtVCPresentationFormatter;
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
use one_core::repository::remote_entity_cache_repository::RemoteEntityCacheRepository;
use one_core::service::certificate::validator::CertificateValidatorImpl;
use one_core::util::clock::DefaultClock;
use one_core::{
    CertificateValidatorCreator, DataProviderCreator, DataTypeCreator, DidMethodCreator,
    FormatterProviderCreator, KeyAlgorithmCreator, KeyStorageCreator, OneCore, OneCoreBuildError,
    OneCoreBuilder, RevocationMethodCreator,
};
use one_crypto::hasher::sha256::SHA256;
use one_crypto::signer::bbs::BBSSigner;
use one_crypto::signer::crydi3::CRYDI3Signer;
use one_crypto::signer::ecdsa::ECDSASigner;
use one_crypto::signer::eddsa::EDDSASigner;
use one_crypto::{CryptoProviderImpl, Hasher, Signer};
use sentry::integrations::tracing::EventFilter;
use serde_json::json;
use sql_data_provider::{DataLayer, DbConn};
use time::Duration;
use tracing_subscriber::prelude::*;

use crate::did_config::{DidUniversalParams, DidWebParams, DidWebVhParams};
use crate::session::CoreServerSessionProvider;
use crate::{ServerConfig, build_info, did_config};

pub async fn initialize_core(
    app_config: &AppConfig<ServerConfig>,
    db_conn: DbConn,
) -> Result<OneCore, OneCoreBuildError> {
    let reqwest_client = reqwest::Client::builder()
        .https_only(!app_config.app.allow_insecure_http_transport)
        .build()
        .expect("Failed to create reqwest::Client");

    let client: Arc<dyn HttpClient> = Arc::new(ReqwestClient::new(reqwest_client));

    let hashers: Vec<(String, Arc<dyn Hasher>)> =
        vec![("sha-256".to_string(), Arc::new(SHA256 {}))];

    let signers: Vec<(String, Arc<dyn Signer>)> = vec![
        ("Ed25519".to_string(), Arc::new(EDDSASigner {})),
        ("ECDSA".to_string(), Arc::new(ECDSASigner {})),
        ("CRYDI3".to_string(), Arc::new(CRYDI3Signer {})),
        ("BBS".to_string(), Arc::new(BBSSigner {})),
    ];

    // TODO figure out a better way to initialize crypto
    let crypto = Arc::new(CryptoProviderImpl::new(
        HashMap::from_iter(hashers),
        HashMap::from_iter(signers),
    ));

    let key_algo_creator: KeyAlgorithmCreator = Box::new(|config, _providers| {
        let mut key_algorithms: HashMap<KeyAlgorithmType, Arc<dyn KeyAlgorithm>> = HashMap::new();

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
            key_algorithms.insert(*name, key_algorithm);
        }

        for (key, value) in config.iter_mut() {
            if let Some(entity) = key_algorithms.get(key) {
                value.capabilities = Some(json!(Into::<KeyAlgorithmCapabilities>::into(
                    entity.get_capabilities()
                )));
            }
        }

        Ok(Arc::new(KeyAlgorithmProviderImpl::new(key_algorithms)))
    });

    let session_provider = Arc::new(CoreServerSessionProvider);

    let data_repository = Arc::new(DataLayer::build(
        db_conn,
        vec!["INTERNAL".to_string(), "AZURE_VAULT".to_owned()],
    ));

    let storage_creator: DataProviderCreator = {
        let data_repository = data_repository.clone();
        Box::new(move || Ok(data_repository))
    };

    let datatype_creator: DataTypeCreator = {
        Box::new(move |config| {
            data_type_provider_from_config(config)
                .map_err(|e| OneCoreBuildError::Config(ConfigError::Validation(e)))
        })
    };

    let cache_entities_config = app_config.core.cache_entities.to_owned();
    let core_base_url = app_config.app.core_base_url.to_owned();
    let data_provider = data_repository.clone();
    let did_method_creator: DidMethodCreator = {
        let client = client.clone();
        Box::new(move |config, providers| {
            let mut did_configs = config.iter().collect::<Vec<_>>();
            // sort by `order`
            did_configs.sort_by(|(_, fields1), (_, fields2)| fields1.order.cmp(&fields2.order));

            let mut did_methods: IndexMap<String, Arc<dyn DidMethod>> = IndexMap::new();
            let mut did_webvh_params: Vec<(String, DidWebVhParams)> = vec![];

            for (name, field) in did_configs {
                let did_method: Arc<dyn DidMethod> = match field.r#type {
                    DidType::Key => {
                        let key_algorithm_provider = providers
                            .key_algorithm_provider
                            .to_owned()
                            .ok_or(OneCoreBuildError::MissingDependency(
                                "key algorithm provider".to_string(),
                            ))?;
                        Arc::new(KeyDidMethod::new(key_algorithm_provider.clone())) as _
                    }
                    DidType::Web => {
                        let params: DidWebParams = config
                            .get(name)
                            .map_err(|e| OneCoreBuildError::Config(ConfigError::Validation(e)))?;
                        let did_web = WebDidMethod::new(
                            &Some(core_base_url.to_owned()),
                            client.clone(),
                            params.into(),
                        )
                        .map_err(|_| {
                            OneCoreBuildError::Config(ConfigError::Validation(
                                ConfigValidationError::EntryNotFound("Base url".to_string()),
                            ))
                        })?;
                        Arc::new(did_web) as _
                    }
                    DidType::Jwk => {
                        let key_algorithm_provider = providers
                            .key_algorithm_provider
                            .to_owned()
                            .ok_or(OneCoreBuildError::MissingDependency(
                                "key algorithm provider".to_string(),
                            ))?;
                        Arc::new(JWKDidMethod::new(key_algorithm_provider.clone())) as _
                    }
                    DidType::Universal => {
                        let params: DidUniversalParams = config
                            .get(name)
                            .map_err(|e| OneCoreBuildError::Config(e.into()))?;
                        Arc::new(UniversalDidMethod::new(params.into(), client.clone())) as _
                    }
                    DidType::WebVh => {
                        let params: DidWebVhParams = config
                            .get(name)
                            .map_err(|e| OneCoreBuildError::Config(e.into()))?;
                        // did:webvh cannot be constructed yet, as it needs a did resolver internally
                        // -> save for later
                        did_webvh_params.push((name.to_string(), params));
                        continue;
                    }
                };
                did_methods.insert(name.to_owned(), did_method);
            }

            let did_caching_loader =
                initialize_did_caching_loader(&cache_entities_config, data_provider.clone());
            let intermediary_provider = Arc::new(DidMethodProviderImpl::new(
                did_caching_loader,
                did_methods.clone(),
            ));

            // Separately construct the did:webvh providers using the intermediary provider
            for (name, params) in did_webvh_params {
                let did_webvh = DidWebVh::new(
                    params.into(),
                    Some(core_base_url.clone()),
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

                    *value = Fields {
                        capabilities: Some(json!(entity.get_capabilities())),
                        params,
                        ..value.clone()
                    }
                }
            }

            let did_caching_loader =
                initialize_did_caching_loader(&cache_entities_config, data_provider);
            Ok(Arc::new(DidMethodProviderImpl::new(
                did_caching_loader,
                did_methods,
            )))
        })
    };

    let key_storage_creator: KeyStorageCreator = {
        let client = client.clone();
        Box::new(move |config, providers| {
            let mut key_providers: HashMap<String, Arc<dyn KeyStorage>> = HashMap::new();

            for (name, field) in config.iter() {
                let provider = match field.r#type {
                    KeyStorageType::Internal => {
                        let params = config
                            .get(name)
                            .map_err(|e| OneCoreBuildError::Config(e.into()))?;
                        Arc::new(InternalKeyProvider::new(
                            providers
                                .key_algorithm_provider
                                .as_ref()
                                .ok_or(OneCoreBuildError::MissingDependency(
                                    "key algorithm provider".to_string(),
                                ))?
                                .clone(),
                            params,
                        )) as _
                    }
                    KeyStorageType::PKCS11 => Arc::new(PKCS11KeyProvider::new()) as _,
                    KeyStorageType::AzureVault => {
                        let params = config
                            .get(name)
                            .map_err(|e| OneCoreBuildError::Config(e.into()))?;
                        Arc::new(AzureVaultKeyProvider::new(
                            params,
                            providers
                                .crypto
                                .as_ref()
                                .ok_or(OneCoreBuildError::MissingDependency(
                                    "crypto provider".to_string(),
                                ))?
                                .clone(),
                            client.clone(),
                        )) as _
                    }
                    other => Err(OneCoreBuildError::Config(ConfigError::Validation(
                        ConfigValidationError::InvalidType(name.to_string(), other.to_string()),
                    )))?,
                };
                key_providers.insert(name.to_owned(), provider);
            }

            for (key, value) in config.iter_mut() {
                if let Some(entity) = key_providers.get(key) {
                    value.capabilities = Some(json!(entity.get_capabilities()));
                }
            }

            Ok(Arc::new(KeyProviderImpl::new(key_providers.to_owned())))
        })
    };

    let caching_loader =
        initialize_jsonld_cache_loader(&app_config.core.cache_entities, data_repository.clone());

    let vct_type_metadata_cache = Arc::new(
        initialize_vct_type_metadata_cache(
            &app_config.core.cache_entities,
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
            let mut credential_formatters: HashMap<String, Arc<dyn CredentialFormatter>> =
                HashMap::new();

            let did_method_provider = providers.did_method_provider.as_ref().ok_or(
                OneCoreBuildError::MissingDependency("did method provider".to_string()),
            )?;

            let key_algorithm_provider = providers.key_algorithm_provider.as_ref().ok_or(
                OneCoreBuildError::MissingDependency("key algorithm provider".to_string()),
            )?;

            let certificate_validator = providers.certificate_validator.as_ref().ok_or(
                OneCoreBuildError::MissingDependency("certificate validator".to_string()),
            )?;

            let crypto = providers
                .crypto
                .as_ref()
                .ok_or(OneCoreBuildError::MissingDependency(
                    "crypto provider".to_string(),
                ))?;

            let datatype_provider = providers.datatype_provider.as_ref().ok_or(
                OneCoreBuildError::MissingDependency("datatype provider".to_string()),
            )?;

            for (name, field) in format_config.iter() {
                let formatter = match field.r#type {
                    FormatType::Jwt => {
                        let params = format_config
                            .get(name)
                            .map_err(|e| OneCoreBuildError::Config(e.into()))?;
                        Arc::new(JWTFormatter::new(
                            params,
                            key_algorithm_provider.clone(),
                            datatype_provider.clone(),
                        )) as _
                    }
                    FormatType::PhysicalCard => Arc::new(PhysicalCardFormatter::new(
                        crypto.clone(),
                        caching_loader.clone(),
                        client.clone(),
                    )) as _,
                    FormatType::SdJwt => {
                        let params = format_config
                            .get(name)
                            .map_err(|e| OneCoreBuildError::Config(e.into()))?;
                        Arc::new(SDJWTFormatter::new(
                            params,
                            crypto.clone(),
                            did_method_provider.clone(),
                            key_algorithm_provider.clone(),
                            datatype_provider.clone(),
                            client.clone(),
                        )) as _
                    }
                    FormatType::SdJwtVc => {
                        let params = format_config
                            .get(name)
                            .map_err(|e| OneCoreBuildError::Config(e.into()))?;
                        Arc::new(SDJWTVCFormatter::new(
                            params,
                            crypto.clone(),
                            did_method_provider.clone(),
                            key_algorithm_provider.clone(),
                            vct_type_metadata_cache.clone(),
                            certificate_validator.clone(),
                            datatype_config.clone(),
                            client.clone(),
                            datatype_provider.clone(),
                        )) as _
                    }
                    FormatType::JsonLdClassic => {
                        let params = format_config
                            .get(name)
                            .map_err(|e| OneCoreBuildError::Config(e.into()))?;
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
                            .map_err(|e| OneCoreBuildError::Config(e.into()))?;
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
                            .map_err(|e| OneCoreBuildError::Config(e.into()))?;

                        Arc::new(MdocFormatter::new(
                            params,
                            certificate_validator.clone(),
                            did_method_provider.clone(),
                            datatype_config.clone(),
                            datatype_provider.clone(),
                            key_algorithm_provider.clone(),
                        )) as _
                    }
                };
                credential_formatters.insert(name.to_owned(), formatter);
            }

            for (key, value) in format_config.iter_mut() {
                if let Some(entity) = credential_formatters.get(key) {
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

            let presentation_formatters: HashMap<String, Arc<dyn PresentationFormatter>> =
                HashMap::from_iter([
                    (
                        "JSON_LD_CLASSIC".to_owned(),
                        Arc::new(LdpVpPresentationFormatter::new(
                            crypto.clone(),
                            caching_loader.clone(),
                            client.clone(),
                        )) as _,
                    ),
                    (
                        "MDOC".to_owned(),
                        Arc::new(MsoMdocPresentationFormatter::new(
                            key_algorithm_provider.clone(),
                            certificate_validator.clone(),
                            providers.core_base_url.clone(),
                        )) as _,
                    ),
                    (
                        "JWT".to_owned(),
                        Arc::new(JwtVpPresentationFormatter::new()) as _,
                    ),
                    // TODO ONE-6774: Remove once productive holders have been updated to release v1.57+
                    (
                        "SD_JWT".to_owned(),
                        Arc::new(SdjwtPresentationFormatter::new(
                            client.clone(),
                            crypto.clone(),
                        )) as _,
                    ),
                    (
                        "SD_JWT_VC".to_owned(),
                        Arc::new(SdjwtVCPresentationFormatter::new(
                            client.clone(),
                            crypto.clone(),
                            certificate_validator.clone(),
                            false,
                        )) as _,
                    ),
                ]);

            let credential_formatter_provider =
                CredentialFormatterProviderImpl::new(credential_formatters);
            let presentation_formatter_provider =
                PresentationFormatterProviderImpl::new(presentation_formatters);
            Ok((
                Arc::new(credential_formatter_provider),
                Arc::new(presentation_formatter_provider),
            ))
        })
    };

    let json_schema_cache = Arc::new(
        initialize_json_schema_loader(
            &app_config.core.cache_entities,
            data_repository.get_remote_entity_cache_repository(),
            client.clone(),
        )
        .await,
    );

    let x509_crl_cache = Arc::new(initialize_x509_crl_cache(
        &app_config.core.cache_entities,
        data_repository.to_owned(),
    )?);

    let android_key_attestation_crl_cache =
        Arc::new(initialize_android_key_attestation_crl_cache()?);

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

            let did_method_provider = providers.did_method_provider.as_ref().ok_or(
                OneCoreBuildError::MissingDependency("did method provider".to_string()),
            )?;

            let key_algorithm_provider = providers.key_algorithm_provider.as_ref().ok_or(
                OneCoreBuildError::MissingDependency("key algorithm provider".to_string()),
            )?;

            let key_provider = providers.key_storage_provider.clone().ok_or(
                OneCoreBuildError::MissingDependency("key storage provider".to_string()),
            )?;

            let formatter_provider = providers.credential_formatter_provider.clone().ok_or(
                OneCoreBuildError::MissingDependency("credential formatter provider".to_string()),
            )?;

            let certificate_validator = providers.certificate_validator.clone().ok_or(
                OneCoreBuildError::MissingDependency("certificate validator".to_string()),
            )?;

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
                        let params = config
                            .get(key)
                            .map_err(|e| OneCoreBuildError::Config(e.into()))?;

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
                            certificate_validator.clone(),
                            client.clone(),
                            Some(params),
                        )) as _
                    }
                    RevocationType::Lvvc => {
                        let params = config
                            .get(key)
                            .map_err(|e| OneCoreBuildError::Config(e.into()))?;
                        Arc::new(LvvcProvider::new(
                            Some(core_base_url.clone()),
                            formatter_provider.clone(),
                            data_repository.get_validity_credential_repository(),
                            key_provider.clone(),
                            key_algorithm_provider.clone(),
                            client.clone(),
                            params,
                        )) as _
                    }
                    RevocationType::TokenStatusList => {
                        let params = config
                            .get(key)
                            .map_err(|e| OneCoreBuildError::Config(e.into()))?;

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
                                certificate_validator.clone(),
                                client.clone(),
                                Some(params),
                            )
                            .map_err(|_| {
                                OneCoreBuildError::Config(ConfigError::Validation(
                                    ConfigValidationError::EntryNotFound(
                                        "Token revocation format must be JWT".to_string(),
                                    ),
                                ))
                            })?,
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
                    certificate_validator: certificate_validator.clone(),
                    client,
                }) as _,
            );

            Ok(Arc::new(RevocationMethodProviderImpl::new(
                revocation_methods,
            )))
        })
    };

    let certificate_validator_creator: CertificateValidatorCreator = {
        Box::new(move |_config, providers| {
            let key_algorithm_provider = providers.key_algorithm_provider.as_ref().ok_or(
                OneCoreBuildError::MissingDependency("key algorithm provider".to_string()),
            )?;

            Ok(Arc::new(CertificateValidatorImpl::new(
                key_algorithm_provider.clone(),
                x509_crl_cache,
                Arc::new(DefaultClock),
                android_key_attestation_crl_cache,
            )))
        })
    };

    OneCoreBuilder::new(app_config.core.clone())
        .with_base_url(app_config.app.core_base_url.to_owned())
        .with_session_provider(session_provider)
        .with_crypto(crypto)
        .with_jsonld_caching_loader(caching_loader)
        .with_data_provider_creator(storage_creator)
        .with_key_algorithm_provider(key_algo_creator)?
        .with_certificate_validator(certificate_validator_creator)?
        .with_key_storage_provider(key_storage_creator)?
        .with_did_method_provider(did_method_creator)?
        .with_datatype_provider(datatype_creator)?
        .with_formatter_provider(formatter_provider_creator)?
        .with_revocation_method_provider(revocation_method_creator)?
        .with_vct_type_metadata_cache(vct_type_metadata_cache)
        .with_json_schema_cache(json_schema_cache)
        .with_trust_listcache(trust_list_cache)
        .with_client(client)
        .with_mqtt_client(Arc::new(RumqttcClient::default()))
        .build()
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

fn initialize_x509_crl_cache(
    cache_entities_config: &CacheEntitiesConfig,
    data_provider: Arc<dyn DataRepository>,
) -> Result<X509CrlCache, OneCoreBuildError> {
    let config: CacheEntityConfig = cache_entities_config
        .entities
        .get("X509_CRL")
        .cloned()
        .unwrap_or(CacheEntityConfig {
            cache_refresh_timeout: Duration::days(1),
            cache_size: 100,
            cache_type: CacheEntityCacheType::Db,
            refresh_after: Duration::days(1),
        });

    let storage: Arc<dyn RemoteEntityStorage> = match config.cache_type {
        CacheEntityCacheType::Db => Arc::new(DbStorage::new(
            data_provider.get_remote_entity_cache_repository(),
        )),
        CacheEntityCacheType::InMemory => Arc::new(InMemoryStorage::new(HashMap::new())),
    };

    let client: Arc<dyn HttpClient> = {
        let client = reqwest::Client::builder()
            .build()
            .expect("Failed to create reqwest::Client");

        Arc::new(ReqwestClient::new(client))
    };

    Ok(X509CrlCache::new(
        Arc::new(X509CrlResolver::new(client)),
        storage,
        config.cache_size as usize,
        config.cache_refresh_timeout,
        config.refresh_after,
    ))
}

fn initialize_android_key_attestation_crl_cache()
-> Result<AndroidAttestationCrlCache, OneCoreBuildError> {
    let client: Arc<dyn HttpClient> = {
        let client = reqwest::Client::builder()
            .build()
            .expect("Failed to create reqwest::Client");

        Arc::new(ReqwestClient::new(client))
    };

    Ok(AndroidAttestationCrlCache::new(
        Arc::new(AndroidAttestationCrlResolver::new(client)),
        Arc::new(InMemoryStorage::new(HashMap::new())),
        1,
        Duration::days(1),
        Duration::days(1),
    ))
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
