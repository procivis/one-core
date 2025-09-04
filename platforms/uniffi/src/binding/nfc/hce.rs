use std::sync::Arc;

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

pub(crate) struct NfcHceWrapper(pub Arc<dyn NfcHce>);

#[async_trait::async_trait]
impl one_core::provider::nfc::hce::NfcHce for NfcHceWrapper {
    async fn is_supported(&self) -> Result<bool, one_core::provider::nfc::NfcError> {
        self.0.is_supported().await.map_err(Into::into)
    }
    async fn is_enabled(&self) -> Result<bool, one_core::provider::nfc::NfcError> {
        self.0.is_enabled().await.map_err(Into::into)
    }
    async fn start_host_data(
        &self,
        data: Vec<u8>,
    ) -> Result<(), one_core::provider::nfc::NfcError> {
        self.0.start_host_data(data).await.map_err(Into::into)
    }
    async fn stop_host_data(&self) -> Result<bool, one_core::provider::nfc::NfcError> {
        self.0.stop_host_data().await.map_err(Into::into)
    }
}
