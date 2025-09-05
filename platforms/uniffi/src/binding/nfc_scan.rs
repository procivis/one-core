use one_core::service::nfc::dto::NfcScanRequestDTO;
use one_dto_mapper::Into;

use super::OneCoreBinding;
use crate::error::BindingError;

#[uniffi::export(async_runtime = "tokio")]
impl OneCoreBinding {
    /// Scan NFC for ISO 18013-5 engagment
    #[uniffi::method]
    pub async fn nfc_read_iso_mdl_engagement(
        &self,
        request: NfcScanRequestBindingDTO,
    ) -> Result<String, BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .nfc_service
            .read_iso_mdl_engagement(request.into())
            .await?)
    }

    /// Cancel previously started NFC scan via `nfc_read_iso_mdl_engagement`
    #[uniffi::method]
    pub async fn nfc_stop_iso_mdl_engagement(&self) -> Result<(), BindingError> {
        let core = self.use_core().await?;
        Ok(core.nfc_service.stop_iso_mdl_engagement().await?)
    }
}

/// Optional messages to be displayed on (iOS) system overlay
#[derive(Clone, Debug, Into, uniffi::Record)]
#[into(NfcScanRequestDTO)]
pub struct NfcScanRequestBindingDTO {
    pub in_progress_message: Option<String>,
    pub failure_message: Option<String>,
    pub success_message: Option<String>,
}
