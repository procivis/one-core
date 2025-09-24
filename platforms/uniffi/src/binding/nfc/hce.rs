use std::sync::Arc;

use crate::error::NfcError;

#[uniffi::export]
#[async_trait::async_trait]
pub trait NfcHceHandler: Send + Sync {
    /// Handle incoming APDU command, return response
    fn handle_command(&self, apdu: Vec<u8>) -> Vec<u8>;

    /// Called when NFC scanner disconnects
    async fn on_scanner_disconnected(&self);

    /// Called when NFC HCE hosting stops
    async fn on_session_stopped(&self, reason: NfcError);
}

/// Provider of NFC host-card emulation (HCE)
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait NfcHce: Send + Sync {
    async fn is_supported(&self) -> Result<bool, NfcError>;
    async fn is_enabled(&self) -> Result<bool, NfcError>;

    /// Starts NFC host-card emulation (HCE)
    /// * `handler` implementation for handling NFC events
    /// * `message` UI message to be placed on the system overlay (iOS)
    async fn start_hosting(
        &self,
        handler: Arc<dyn NfcHceHandler>,
        message: Option<String>,
    ) -> Result<(), NfcError>;

    /// stops emulation started via `start_hosting`
    /// * `success` true if hosting should be ended with a success or failure (iOS)
    async fn stop_hosting(&self, success: bool) -> Result<(), NfcError>;
}

pub(crate) struct NfcHceWrapper(pub Arc<dyn NfcHce>);

#[async_trait::async_trait]
impl one_core::provider::nfc::hce::NfcHce for NfcHceWrapper {
    async fn is_supported(&self) -> Result<bool, one_core::provider::nfc::NfcError> {
        self.0.is_supported().await.map_err(Into::into)
    }
    async fn is_enabled(&self) -> Result<bool, one_core::provider::nfc::NfcError> {
        self.0.is_enabled().await.map_err(Into::into)
    }
    async fn start_hosting(
        &self,
        handler: Arc<dyn one_core::provider::nfc::hce::NfcHceHandler>,
        message: Option<String>,
    ) -> Result<(), one_core::provider::nfc::NfcError> {
        self.0
            .start_hosting(Arc::new(handler), message)
            .await
            .map_err(Into::into)
    }
    async fn stop_hosting(&self, success: bool) -> Result<(), one_core::provider::nfc::NfcError> {
        self.0.stop_hosting(success).await.map_err(Into::into)
    }
}

#[async_trait::async_trait]
impl NfcHceHandler for Arc<dyn one_core::provider::nfc::hce::NfcHceHandler> {
    fn handle_command(&self, apdu: Vec<u8>) -> Vec<u8> {
        self.as_ref().handle_command(apdu)
    }

    async fn on_scanner_disconnected(&self) {
        self.as_ref().on_scanner_disconnected().await
    }

    async fn on_session_stopped(&self, reason: NfcError) {
        self.as_ref().on_session_stopped(reason.into()).await
    }
}
