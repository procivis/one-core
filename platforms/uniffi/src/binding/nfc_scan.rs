use one_core::service::error::ServiceError;

use super::OneCoreBinding;
use crate::error::BindingError;

#[uniffi::export(async_runtime = "tokio")]
impl OneCoreBinding {
    /// Scan NFC for ISO 18013-5 engagment
    #[uniffi::method]
    pub async fn nfc_read_iso_mdl_engagement(
        &self,
        _request: NfcScanRequestBindingDTO,
    ) -> Result<String, BindingError> {
        Err(ServiceError::Other("Not implemented".to_string()).into())
    }

    /// Cancel previously started NFC scan via `nfc_read_iso_mdl_engagement`
    #[uniffi::method]
    pub async fn nfc_stop_iso_mdl_engagement(&self) -> Result<(), BindingError> {
        Err(ServiceError::Other("Not implemented".to_string()).into())
    }
}

/// Optional messages to be displayed on (iOS) system overlay
#[derive(Clone, Debug, uniffi::Record)]
pub struct NfcScanRequestBindingDTO {
    pub in_progress_message: Option<String>,
    pub failure_message: Option<String>,
    pub success_message: Option<String>,
}
