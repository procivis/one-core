#![cfg_attr(feature = "strict", deny(warnings))]

use std::sync::Arc;
mod utils;
use sql_data_provider::DataLayer;
use tokio::sync::RwLock;
use utils::run_sync;

mod functions;
use functions::*;

use one_core::config::{
    data_structure::{ConfigKind, UnparsedConfig},
    ConfigParseError,
};

use utils::dto::CredentialState;

uniffi::include_scaffolding!("one_core");

pub struct ActiveProof {
    id: String,
    base_url: String,
}

pub struct OneCore {
    inner: one_core::OneCore,

    // FIXME: temporary solution for proof submit/reject until interaction is developed
    active_proof: RwLock<Option<ActiveProof>>,
}

fn initialize_core(data_dir_path: String) -> Result<Arc<OneCore>, ConfigParseError> {
    let placeholder_config = UnparsedConfig {
        content: include_str!("../../../config.yml").to_string(),
        kind: ConfigKind::Yaml,
    };
    let core = run_sync(async {
        one_core::OneCore::new(
            Arc::new(
                DataLayer::create(
                    format!("sqlite:{data_dir_path}/one_core_db.sqlite?mode=rwc").as_str(),
                )
                .await,
            ),
            placeholder_config,
        )
    })?;
    Ok(Arc::new(OneCore {
        inner: core,
        active_proof: RwLock::new(None),
    }))
}
