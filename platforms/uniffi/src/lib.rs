#![cfg_attr(feature = "strict", deny(warnings))]

use one_core::{
    config::{
        data_structure::{ConfigKind, UnparsedConfig},
        ConfigParseError,
    },
    service::{did::dto::DidId, error::ServiceError, proof::dto::ProofId},
};
use sql_data_provider::DataLayer;
use std::sync::Arc;
use tokio::sync::RwLock;
use utils::run_sync;

mod dto;
mod functions;
mod mapper;
mod utils;

use dto::*;
uniffi::include_scaffolding!("one_core");

pub struct ActiveProof {
    id: ProofId,
    base_url: String,
    did_id: DidId,
}

pub struct OneCoreBinding {
    inner: one_core::OneCore,

    // FIXME: temporary solution for proof submit/reject until interaction is developed
    active_proof: RwLock<Option<ActiveProof>>,
}

fn initialize_core(data_dir_path: String) -> Result<Arc<OneCoreBinding>, ConfigParseError> {
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
    Ok(Arc::new(OneCoreBinding {
        inner: core,
        active_proof: RwLock::new(None),
    }))
}
