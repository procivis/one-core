#![cfg_attr(feature = "strict", deny(warnings))]

use error::{BindingError, NativeKeyStorageError};
use one_core::config::core_config;
use sql_data_provider::{self, DataLayer};
use std::sync::Arc;
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
    native_key_storage: Option<Box<dyn NativeKeyStorage>>,
) -> Result<Arc<OneCoreBinding>, BindingError> {
    let placeholder_config =
        core_config::CoreConfig::from_yaml_str(include_str!("../../../mobile_config.yml"))?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| BindingError::Unknown(e.to_string()))?;

    let db_path = format!("{data_dir_path}/one_core_db.sqlite");
    let core = runtime.block_on(async {
        let db_url = format!("sqlite:{db_path}?mode=rwc");
        let db_conn = sql_data_provider::db_conn(db_url).await;

        one_core::OneCore::new(
            Arc::new(DataLayer::build(db_conn)),
            placeholder_config,
            None,
            native_key_storage.map(|storage| {
                Arc::new(NativeKeyStorageWrapper(storage))
                    as Arc<dyn one_core::provider::key_storage::secure_element::NativeKeyStorage>
            }),
        )
    })?;
    Ok(Arc::new(OneCoreBinding::new(core, db_path, runtime)))
}
