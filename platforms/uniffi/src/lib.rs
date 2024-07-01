#![cfg_attr(feature = "strict", deny(warnings))]

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use error::{BindingError, BleErrorWrapper, NativeKeyStorageError};
use one_core::config::core_config::{self, AppConfig, JsonLdContextConfig};
use one_core::provider::bluetooth_low_energy::BleError;
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

uniffi::include_scaffolding!("one_core");

fn initialize_core(
    data_dir_path: String,
    config_mobile: &'static str,
    native_key_storage: Option<Box<dyn NativeKeyStorage>>,
    ble_central: Option<Arc<dyn BleCentral>>,
    ble_peripheral: Option<Arc<dyn BlePeripheral>>,
) -> Result<Arc<OneCoreBinding>, BindingError> {
    let native_key_storage =
        native_key_storage.map(|storage| Arc::new(NativeKeyStorageWrapper(storage)) as _);

    let ble_central = ble_central.map(|central| Arc::new(BleCentralWrapper(central)) as _);
    let ble_peripheral =
        ble_peripheral.map(|peripheral| Arc::new(BlePeripheralWrapper(peripheral)) as _);

    let config = include_str!("../../../config/config.yml");
    let config_base = include_str!("../../../config/config-procivis-base.yml");

    let placeholder_config: AppConfig<MobileConfig> =
        core_config::AppConfig::from_yaml_str_configs(vec![config, config_base, config_mobile])?;

    let runtime = tokio::runtime::Builder::new_current_thread()
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

        let json_ld_context_config = placeholder_config.app.json_ld_context.to_owned();
        Box::pin(async move {
            let db_url = format!("sqlite:{db_path}?mode=rwc");
            let db_conn = sql_data_provider::db_conn(db_url, true)
                .await
                .map_err(|e| BindingError::DbErr(e.to_string()))?;

            Ok(one_core::OneCore::new(
                |exportable_storages| Arc::new(DataLayer::build(db_conn, exportable_storages)),
                core_config,
                None,
                native_key_storage,
                json_ld_context_config,
                ble_peripheral,
                ble_central,
            )?)
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
    pub json_ld_context: Option<JsonLdContextConfig>,
}
