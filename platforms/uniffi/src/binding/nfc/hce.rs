use crate::error::NfcError;

/// Provider of NFC host-card emulation (HCE)
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait NfcHce: Send + Sync {
    async fn is_supported(&self) -> Result<bool, NfcError>;
    async fn is_enabled(&self) -> Result<bool, NfcError>;

    /// Starts NFC host-card emulation (HCE), with static data
    async fn start_host_data(&self, data: Vec<u8>) -> Result<(), NfcError>;

    /// stops emulation started via `start_host_data`
    /// returns `true` if hosted data was read by an NFC scanner
    async fn stop_host_data(&self) -> Result<bool, NfcError>;
}
