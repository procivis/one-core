#![cfg_attr(feature = "strict", deny(warnings))]

use std::path::Path;
use std::sync::{Arc, LazyLock};

use one_core::OneCore;
use one_core::config::core_config::{self, AppConfig, InputFormat};
use one_core::proto::http_client::HttpClient;
use one_core::proto::http_client::reqwest_client::ReqwestClient;
use one_core::proto::session_provider::NoSessionProvider;
use one_core::repository::error::DataLayerError;
use one_core::service::error::ServiceError;
use serde::{Deserialize, Serialize};
use sql_data_provider::DataLayer;
use tracing::warn;

use crate::binding::OneCoreBinding;
use crate::binding::ble::{BleCentral, BleCentralWrapper, BlePeripheral, BlePeripheralWrapper};
use crate::binding::key_storage::{NativeKeyStorage, NativeKeyStorageWrapper};
use crate::binding::nfc::hce::{NfcHce, NfcHceWrapper};
use crate::binding::nfc::scanner::{NfcScanner, NfcScannerWrapper};
use crate::error::{BindingError, SDKError};

mod binding;
mod error;
mod utils;

#[cfg(test)]
mod test;

uniffi::setup_scaffolding!();

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
struct MobileConfig {
    pub allow_insecure_http_transport: bool,
    pub trace_level: Option<String>,
}

#[derive(Default, uniffi::Record)]
pub struct InitParamsDTO {
    pub config_json: Option<String>,
    pub native_secure_element: Option<Arc<dyn NativeKeyStorage>>,
    pub remote_secure_element: Option<Arc<dyn NativeKeyStorage>>,
    pub ble_central: Option<Arc<dyn BleCentral>>,
    pub ble_peripheral: Option<Arc<dyn BlePeripheral>>,
    pub nfc_hce: Option<Arc<dyn NfcHce>>,
    pub nfc_scanner: Option<Arc<dyn NfcScanner>>,
}

#[uniffi::export]
fn initialize_core(
    data_dir_path: String,
    params: InitParamsDTO,
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

    rt.block_on(initialize(data_dir_path, params))
}

async fn initialize(
    data_dir_path: String,
    params: InitParamsDTO,
) -> Result<Arc<OneCoreBinding>, BindingError> {
    let native_secure_element: Option<
        Arc<dyn one_core::provider::key_storage::secure_element::NativeKeyStorage>,
    > = params
        .native_secure_element
        .map(|storage| Arc::new(NativeKeyStorageWrapper(storage)) as _);

    let remote_secure_element: Option<
        Arc<dyn one_core::provider::key_storage::secure_element::NativeKeyStorage>,
    > = params
        .remote_secure_element
        .map(|storage| Arc::new(NativeKeyStorageWrapper(storage)) as _);

    let ble_central = params
        .ble_central
        .map(|central| Arc::new(BleCentralWrapper(central)) as _);
    let ble_peripheral = params
        .ble_peripheral
        .map(|peripheral| Arc::new(BlePeripheralWrapper(peripheral)) as _);

    let nfc_hce = params.nfc_hce.map(|hce| Arc::new(NfcHceWrapper(hce)) as _);
    let nfc_scanner = params
        .nfc_scanner
        .map(|hce| Arc::new(NfcScannerWrapper(hce)) as _);

    let cfg = build_config(params.config_json.as_deref().unwrap_or("{}"))?;

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
        let subscriber = subscriber.with(tracing_oslog::OsLogger::new(
            "ch.procivis.one.core",
            "default",
        ));

        #[allow(unused_must_use)]
        subscriber.try_init();
    }

    let path = Path::new(&data_dir_path);
    let main_db_path = path
        .join("one_core_db.sqlite")
        .to_str()
        .ok_or(SDKError::InitializationFailure(
            "invalid data_dir_path".to_string(),
        ))?
        .to_owned();
    let backup_db_path = path
        .join("backup_one_core_db.sqlite")
        .to_str()
        .ok_or(SDKError::InitializationFailure(
            "invalid data_dir_path".to_string(),
        ))?
        .to_owned();

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
        let nfc_hce = nfc_hce.clone();
        let nfc_scanner = nfc_scanner.clone();

        Box::pin(async move {
            let db_url = format!("sqlite:{db_path}?mode=rwc");
            let db_conn = sql_data_provider::db_conn(db_url, true)
                .await
                .map_err(|e| ServiceError::Repository(DataLayerError::Db(e.into())))?;
            let data_repository = Arc::new(DataLayer::build(db_conn, vec!["INTERNAL".to_string()]));

            let reqwest_client = reqwest::Client::builder()
                .https_only(!cfg.app.allow_insecure_http_transport)
                .build()
                .map_err(|_| {
                    SDKError::InitializationFailure("Failed to create reqwest::Client".to_string())
                })?;
            let client: Arc<dyn HttpClient> = Arc::new(ReqwestClient::new(reqwest_client));
            let session_provider = Arc::new(NoSessionProvider);

            OneCore::new(
                core_config,
                None,
                session_provider,
                data_repository,
                client,
                ble_peripheral,
                ble_central,
                nfc_hce,
                nfc_scanner,
                native_secure_element,
                remote_secure_element,
            )
            .await
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

fn build_config(config: &str) -> Result<AppConfig<MobileConfig>, SDKError> {
    core_config::AppConfig::parse([
        InputFormat::yaml_str(include_str!("../../../config/config.yml")),
        InputFormat::yaml_str(include_str!("../../../config/config-procivis-base.yml")),
        InputFormat::yaml_str(include_str!("../../../config/config-procivis-mobile.yml")),
        InputFormat::json_str(config),
    ])
    .map_err(|err| SDKError::InitializationFailure(err.to_string()))
}

#[cfg(test)]
mod tests {

    use crate::build_config;

    #[test]
    fn test_build_config_parses_static_configs() {
        assert!(build_config("{}").is_ok());
    }
}
