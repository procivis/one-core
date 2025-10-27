use super::NfcError;

/// Provider of NFC scanner functionality
#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait NfcScanner: Send + Sync {
    /// Check whether NFC scanning is supported on the device
    async fn is_supported(&self) -> Result<bool, NfcError>;

    /// Check whether NFC adapter is enabled on the device (android only)
    async fn is_enabled(&self) -> Result<bool, NfcError>;

    /// Starts scanning for ISO 7816-4 NFC tag
    /// * `message` - UI message to display on the NFC overlay (iOS)
    ///
    /// This function returns when:
    /// * an IsoDep tag is scanned and session established
    /// * on cancellation (`cancel_scan`) - `NfcError::Cancelled`
    /// * or on failure
    async fn scan(&self, message: Option<String>) -> Result<(), NfcError>;

    /// Update UI message on the NFC scanner overlay (iOS) - previously set via `scan`
    async fn set_message(&self, message: String) -> Result<(), NfcError>;

    /// Stops scanning previously started via `scan`
    /// or disconnects the established session
    async fn cancel_scan(&self, error_message: Option<String>) -> Result<(), NfcError>;

    /// Send APDU request and wait for response APDU
    async fn transceive(&self, command_apdu: Vec<u8>) -> Result<Vec<u8>, NfcError>;
}
