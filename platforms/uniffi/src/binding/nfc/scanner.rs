use std::sync::Arc;

use crate::error::NfcError;

/// Provider of NFC scanner functionality
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait NfcScanner: Send + Sync {
    /// Check whether NFC scanning is supported on the device
    async fn is_supported(&self) -> Result<bool, NfcError>;

    /// Check whether NFC adapter is enabled on the device (android only, iOS always enabled)
    async fn is_enabled(&self) -> Result<bool, NfcError>;

    /// Starts scanning for ISO 7816-4 NFC tag
    /// * `message` - UI message to display on the system NFC overlay (iOS)
    ///
    /// This function returns when:
    /// * an IsoDep tag is scanned and session established
    /// * on cancellation (`cancel_scan`) - `NfcError::Cancelled`
    /// * or on failure
    async fn scan(&self, message: Option<String>) -> Result<(), NfcError>;

    /// Update UI message on the system NFC scanner overlay (iOS) - previously set via `scan`
    async fn set_message(&self, message: String) -> Result<(), NfcError>;

    /// Stops scanning previously started via `scan`
    /// or disconnects the established session
    /// * `error_message` - error UI message to display on the system NFC overlay (iOS)
    async fn cancel_scan(&self, error_message: Option<String>) -> Result<(), NfcError>;

    /// Send APDU request and wait for response APDU
    async fn transceive(&self, command_apdu: Vec<u8>) -> Result<Vec<u8>, NfcError>;
}

pub(crate) struct NfcScannerWrapper(pub Arc<dyn NfcScanner>);

#[async_trait::async_trait]
impl one_core::provider::nfc::scanner::NfcScanner for NfcScannerWrapper {
    async fn is_supported(&self) -> Result<bool, one_core::provider::nfc::NfcError> {
        self.0.is_supported().await.map_err(Into::into)
    }
    async fn is_enabled(&self) -> Result<bool, one_core::provider::nfc::NfcError> {
        self.0.is_enabled().await.map_err(Into::into)
    }
    async fn scan(&self, message: Option<String>) -> Result<(), one_core::provider::nfc::NfcError> {
        self.0.scan(message).await.map_err(Into::into)
    }
    async fn set_message(&self, message: String) -> Result<(), one_core::provider::nfc::NfcError> {
        self.0.set_message(message).await.map_err(Into::into)
    }
    async fn cancel_scan(
        &self,
        error_message: Option<String>,
    ) -> Result<(), one_core::provider::nfc::NfcError> {
        self.0.cancel_scan(error_message).await.map_err(Into::into)
    }
    async fn transceive(
        &self,
        command_apdu: Vec<u8>,
    ) -> Result<Vec<u8>, one_core::provider::nfc::NfcError> {
        self.0.transceive(command_apdu).await.map_err(Into::into)
    }
}
