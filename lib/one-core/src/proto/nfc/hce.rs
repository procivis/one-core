use std::sync::Arc;

use super::NfcError;

#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait NfcHceHandler: Send + Sync {
    fn handle_command(&self, apdu: Vec<u8>) -> Vec<u8>;
    async fn on_scanner_disconnected(&self);
    async fn on_session_stopped(&self, reason: NfcError);
}

/// Provider of NFC host-card emulation (HCE)
#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait NfcHce: Send + Sync {
    async fn is_supported(&self) -> Result<bool, NfcError>;
    async fn is_enabled(&self) -> Result<bool, NfcError>;

    async fn start_hosting(
        &self,
        handler: Arc<dyn NfcHceHandler>,
        message: Option<String>,
    ) -> Result<(), NfcError>;

    async fn stop_hosting(&self, success: bool) -> Result<(), NfcError>;
}
