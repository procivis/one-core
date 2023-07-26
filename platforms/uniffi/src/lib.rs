#![cfg_attr(feature = "strict", deny(warnings))]

use std::sync::Arc;
mod utils;
use utils::run_sync;

mod functions;
use functions::*;

uniffi::include_scaffolding!("one_core");

pub struct OneCore {
    inner: one_core::OneCore,
}

fn initialize_core(data_dir_path: String) -> Arc<OneCore> {
    let core = run_sync(async {
        one_core::OneCore::new(
            format!("sqlite:{data_dir_path}/one_core_db.sqlite?mode=rwc").as_str(),
        )
        .await
    });
    Arc::new(OneCore { inner: core })
}
