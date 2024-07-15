#![cfg_attr(feature = "strict", deny(warnings))]

use std::{collections::HashMap, sync::Arc};

use one_providers::{
    crypto::{
        imp::{
            hasher::sha256::SHA256,
            signer::{
                bbs::BBSSigner, crydi3::CRYDI3Signer, eddsa::EDDSASigner, es256::ES256Signer,
            },
            CryptoProviderImpl,
        },
        Hasher, Signer,
    },
    key_algorithm::{
        imp::{bbs::BBS, eddsa::Eddsa, es256::Es256, provider::KeyAlgorithmProviderImpl},
        KeyAlgorithm,
    },
    key_storage::{imp::provider::KeyProviderImpl, KeyStorage},
};
use serde::{Deserialize, Serialize};

use error::{BindingError, BleErrorWrapper, NativeKeyStorageError};
use one_core::{
    config::core_config::{self, AppConfig},
    provider::{
        key_algorithm::ml_dsa::MlDsa, key_storage::secure_element::SecureElementKeyProvider,
    },
    DataProviderCreator, KeyStorageCreator, OneCoreBuilder,
};
use one_core::{provider::bluetooth_low_energy::BleError, KeyAlgorithmCreator};
use sql_data_provider::DataLayer;
use utils::native_ble_central::BleCentralWrapper;
use utils::native_ble_peripheral::BlePeripheralWrapper;
use utils::native_key_storage::NativeKeyStorageWrapper;

mod binding;
mod dto;
mod error;
mod functions;
mod mapper;
mod utils;

use binding::OneCoreBinding;
use dto::*;
use one_core::config::core_config::CacheEntitiesConfig;

uniffi::include_scaffolding!("one_core");

fn initialize_core(
    data_dir_path: String,
    config_mobile: &'static str,
    native_key_storage: Option<Box<dyn dto::NativeKeyStorage>>,
    ble_central: Option<Arc<dyn BleCentral>>,
    ble_peripheral: Option<Arc<dyn BlePeripheral>>,
) -> Result<Arc<OneCoreBinding>, BindingError> {
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

        let cache_entities_config = placeholder_config.app.cache_entities.to_owned();
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

            let key_storage_creator: KeyStorageCreator = Box::new(move |config, _providers| {
                let mut key_providers: HashMap<String, Arc<dyn KeyStorage>> = HashMap::new();

                for (name, field) in config.iter() {
                    let provider = match field.r#type.as_str() {
                        "SECURE_ELEMENT" => {
                            let local_native_key_storage: Arc<dyn one_core::provider::key_storage::secure_element::NativeKeyStorage> =
                                native_key_storage.clone().expect("Missing native key provider");
                            let params =
                                config.get(name).expect("Secure element config is required");
                            Arc::new(SecureElementKeyProvider::new(
                                local_native_key_storage.clone(),
                                params,
                            )) as _
                        }
                        other => panic!("Unexpected key storage: {other}"),
                    };
                    key_providers.insert(name.to_owned(), provider);
                }

                Arc::new(KeyProviderImpl::new(key_providers.to_owned()))
            });

            let storage_creator: DataProviderCreator =
                Box::new(|| Arc::new(DataLayer::build(db_conn, vec![])));

            OneCoreBuilder::new(core_config.clone())
                .with_crypto(crypto)
                .with_data_provider_creator(storage_creator)
                .with_cache_entities_config(cache_entities_config)
                .with_key_algorithm_provider(key_algo_creator)
                .with_key_storage_provider(key_storage_creator)
                .with_ble(ble_peripheral, ble_central)
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
    #[serde(default)]
    pub cache_entities: Option<CacheEntitiesConfig>,
}
