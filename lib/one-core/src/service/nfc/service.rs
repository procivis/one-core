use ct_codecs::{Base64UrlSafeNoPadding, Encoder};

use super::NfcService;
use super::dto::NfcScanRequestDTO;
use crate::config::core_config::VerificationEngagement;
use crate::provider::nfc::scanner::NfcScanner;
use crate::service::error::{ServiceError, ValidationError};

impl NfcService {
    pub async fn read_iso_mdl_engagement(
        &self,
        request: NfcScanRequestDTO,
    ) -> Result<String, ServiceError> {
        let enabled = self
            .config
            .verification_engagement
            .get(&VerificationEngagement::NFC)
            .map(|config| config.enabled.unwrap_or(true))
            .unwrap_or(false);
        if !enabled {
            return Err(ValidationError::MissingVerificationEngagementConfig(
                "NFC engagement not enabled".to_string(),
            )
            .into());
        }

        let Some(nfc_scanner) = self.nfc_scanner.as_ref() else {
            return Err(ServiceError::Other("Not supported".to_string()));
        };

        nfc_scanner.scan(request.in_progress_message).await?;

        // NFC tag discovered - read data
        let result = read_select_handover(nfc_scanner.as_ref()).await;

        // reading finished - display result
        let final_message = match &result {
            Ok(_) => request.success_message,
            Err(_) => request.failure_message,
        };

        if let Some(final_message) = final_message {
            nfc_scanner
                .set_message(final_message)
                .await
                .unwrap_or_else(|err| {
                    tracing::warn!("Failed to write final message: {err}");
                });
        }

        // done - close session
        let _unused = nfc_scanner.cancel_scan().await;

        result
    }

    pub async fn stop_iso_mdl_engagement(&self) -> Result<(), ServiceError> {
        let Some(nfc_scanner) = self.nfc_scanner.as_ref() else {
            return Err(ServiceError::Other("Not supported".to_string()));
        };

        nfc_scanner.cancel_scan().await.map_err(Into::into)
    }
}

async fn read_select_handover(scanner: &dyn NfcScanner) -> Result<String, ServiceError> {
    selection(
        scanner,
        command::select_application(&ndef_id::MDOC_ENGAGEMENT_APPLICATION_ID),
    )
    .await?;

    selection(
        scanner,
        command::select_file(&ndef_id::CAPABILITY_CONTAINER_FILE_ID),
    )
    .await?;

    let capability_container = read(scanner, 0, 15).await?;
    if capability_container.len() != 15 {
        return Err(ServiceError::Other(format!(
            "Invalid CC length: {}",
            capability_container.len()
        )));
    }

    let ndef_file_id = &capability_container.as_slice()[9..11];
    selection(scanner, command::select_file(ndef_file_id)).await?;

    let ndef_length = read(scanner, 0, 2).await?;
    let ndef_length = u16::from_be_bytes(ndef_length.try_into().map_err(|bytes| {
        ServiceError::MappingError(format!("Could not parse ndef length: {bytes:?}"))
    })?);

    let ndef = read(scanner, 2, ndef_length).await?;
    tracing::debug!("Handover Select message: {ndef:?}");

    Base64UrlSafeNoPadding::encode_to_string(ndef)
        .map_err(|e| ServiceError::MappingError(e.to_string()))
}

async fn selection(session: &dyn NfcScanner, command: Vec<u8>) -> Result<(), ServiceError> {
    let data = session.transceive(command).await?;

    if data != response::SUCCESS {
        return Err(ServiceError::Other(format!(
            "APDU selection failed: {data:?}"
        )));
    }

    Ok(())
}

async fn read(session: &dyn NfcScanner, offset: u16, length: u16) -> Result<Vec<u8>, ServiceError> {
    let mut data = session
        .transceive(command::read_binary(offset, length))
        .await?;

    let status = data.split_off(data.len() - 2);

    if status != response::SUCCESS {
        return Err(ServiceError::Other(format!("APDU read failed: {status:?}")));
    }

    Ok(data)
}

mod ndef_id {
    pub(super) const MDOC_ENGAGEMENT_APPLICATION_ID: [u8; 7] =
        [0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01];

    pub(super) const CAPABILITY_CONTAINER_FILE_ID: [u8; 2] = [0xE1, 0x03];
}

mod command {
    use apdu_core::Command;

    const INS_SELECT: u8 = 0xA4;
    const INS_READ_BINARY: u8 = 0xB0;

    type Params = (u8, u8);
    const SELECT_APPLICATION: Params = (0x04, 0x00);
    const SELECT_FILE: Params = (0x00, 0x0C);

    pub(super) fn select_application(application_id: &[u8]) -> Vec<u8> {
        Command::new_with_payload(
            0x00,
            INS_SELECT,
            SELECT_APPLICATION.0,
            SELECT_APPLICATION.1,
            application_id,
        )
        .into()
    }

    pub(super) fn select_file(file_id: &[u8]) -> Vec<u8> {
        Command::new_with_payload(0x00, INS_SELECT, SELECT_FILE.0, SELECT_FILE.1, file_id).into()
    }

    pub(super) fn read_binary(offset: u16, length: u16) -> Vec<u8> {
        let [p1, p2] = offset.to_be_bytes();
        Command::new_with_le(0x00, INS_READ_BINARY, p1, p2, length).into()
    }
}

mod response {
    type SW1_2 = [u8; 2];
    pub(super) const SUCCESS: SW1_2 = [0x90, 0x00];
}
