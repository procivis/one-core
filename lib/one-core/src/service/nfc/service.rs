use ct_codecs::{Base64UrlSafeNoPadding, Encoder};

use super::NfcService;
use super::dto::NfcScanRequestDTO;
use crate::config::core_config::VerificationEngagement;
use crate::provider::nfc::NfcError;
use crate::provider::nfc::apdu::Response;
use crate::provider::nfc::command::KnownCommand;
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
        if result.is_ok() {
            if let Some(final_message) = request.success_message {
                nfc_scanner
                    .set_message(final_message)
                    .await
                    .unwrap_or_else(|err| {
                        tracing::warn!("Failed to write final message: {err}");
                    });
            }
        }

        let error_message = match &result {
            Ok(_) => None,
            Err(err) => Some(request.failure_message.unwrap_or(err.to_string())),
        };

        // done - close session
        nfc_scanner
            .cancel_scan(error_message)
            .await
            .unwrap_or_else(|err| {
                tracing::warn!("Failed to close scanner: {err}");
            });

        result
    }

    pub async fn stop_iso_mdl_engagement(&self) -> Result<(), ServiceError> {
        let Some(nfc_scanner) = self.nfc_scanner.as_ref() else {
            return Err(ServiceError::Other("Not supported".to_string()));
        };

        nfc_scanner.cancel_scan(None).await.map_err(Into::into)
    }
}

async fn read_select_handover(scanner: &dyn NfcScanner) -> Result<String, ServiceError> {
    selection(
        scanner,
        KnownCommand::SelectApplication {
            application_id: ndef_id::MDOC_ENGAGEMENT_APPLICATION_ID.to_vec(),
        },
    )
    .await?;

    selection(
        scanner,
        KnownCommand::SelectFile {
            file_id: ndef_id::CAPABILITY_CONTAINER_FILE_ID,
        },
    )
    .await?;

    let capability_container = read(scanner, 0, 15).await?;
    if capability_container.len() != 15 {
        return Err(ServiceError::Other(format!(
            "Invalid CC length: {}",
            capability_container.len()
        )));
    }

    let ndef_file_id: [u8; 2] = capability_container.as_slice()[9..11]
        .try_into()
        .map_err(|e: std::array::TryFromSliceError| ServiceError::MappingError(e.to_string()))?;
    selection(
        scanner,
        KnownCommand::SelectFile {
            file_id: ndef_file_id,
        },
    )
    .await?;

    let ndef_length = read(scanner, 0, 2).await?;
    let ndef_length = u16::from_be_bytes(ndef_length.try_into().map_err(|bytes| {
        ServiceError::MappingError(format!("Could not parse ndef length: {bytes:?}"))
    })?);

    let ndef = read(scanner, 2, ndef_length as _).await?;
    tracing::debug!("Handover Select message: {ndef:?}");

    Base64UrlSafeNoPadding::encode_to_string(ndef)
        .map_err(|e| ServiceError::MappingError(e.to_string()))
}

async fn selection(session: &dyn NfcScanner, command: KnownCommand) -> Result<(), ServiceError> {
    let response = run_command(session, command).await?;
    if !response.is_success() {
        return Err(ServiceError::Other(format!(
            "APDU selection failed: {response:?}"
        )));
    }

    Ok(())
}

async fn read(
    session: &dyn NfcScanner,
    offset: u16,
    length: usize,
) -> Result<Vec<u8>, ServiceError> {
    let response = run_command(session, KnownCommand::ReadBinary { offset, length }).await?;
    if !response.is_success() {
        return Err(ServiceError::Other(format!(
            "APDU read failed: {response:?}"
        )));
    }

    Ok(response.payload)
}

async fn run_command(
    session: &dyn NfcScanner,
    command: KnownCommand,
) -> Result<Response, NfcError> {
    session
        .transceive(
            command
                .try_into()
                .map_err(|err: anyhow::Error| NfcError::Unknown {
                    reason: err.to_string(),
                })?,
        )
        .await?
        .try_into()
        .map_err(|err: anyhow::Error| NfcError::Unknown {
            reason: err.to_string(),
        })
}

mod ndef_id {
    pub(super) const MDOC_ENGAGEMENT_APPLICATION_ID: [u8; 7] =
        [0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01];

    pub(super) const CAPABILITY_CONTAINER_FILE_ID: [u8; 2] = [0xE1, 0x03];
}
