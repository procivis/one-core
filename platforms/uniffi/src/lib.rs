#![cfg_attr(feature = "strict", deny(warnings))]

use error::{BindingError, NativeKeyStorageError};
use one_core::config::core_config;
use sql_data_provider::{self, DataLayer};
use std::sync::Arc;
use utils::{native_key_storage::NativeKeyStorageWrapper, run_sync};

mod dto;
mod error;
mod functions;
mod mapper;
mod utils;

use dto::*;
uniffi::include_scaffolding!("one_core");

pub struct OneCoreBinding {
    inner: one_core::OneCore,
}

fn initialize_core(
    data_dir_path: String,
    native_key_storage: Option<Box<dyn NativeKeyStorage>>,
) -> Result<Arc<OneCoreBinding>, BindingError> {
    let placeholder_config =
        core_config::CoreConfig::from_yaml_str(include_str!("../../../mobile_config.yml"))?;

    let core = run_sync(async {
        let db_url = format!("sqlite:{data_dir_path}/one_core_db.sqlite?mode=rwc");
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
    Ok(Arc::new(OneCoreBinding { inner: core }))
}
