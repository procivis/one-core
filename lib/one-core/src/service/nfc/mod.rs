use std::sync::Arc;

use crate::config::core_config;
use crate::provider::nfc::scanner::NfcScanner;

pub mod dto;
mod service;

#[derive(Clone)]
pub struct NfcService {
    config: Arc<core_config::CoreConfig>,
    nfc_scanner: Option<Arc<dyn NfcScanner>>,
}

impl NfcService {
    pub fn new(
        config: Arc<core_config::CoreConfig>,
        nfc_scanner: Option<Arc<dyn NfcScanner>>,
    ) -> Self {
        Self {
            config,
            nfc_scanner,
        }
    }
}
