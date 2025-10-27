// NFC static handover handling according to ISO 18013-5 (mDL) and NFC Forum, Connection Handover (CH) Technical Specification, Version 1.5

use std::sync::{Arc, Mutex};

use anyhow::bail;
use tokio::sync::oneshot;

use super::NfcError;
use super::apdu::Response;
use super::command::{FileId, KnownCommand};
use super::hce::{NfcHce, NfcHceHandler};

/// Wraps NFC Static handover functionality
pub(crate) struct NfcStaticHandoverHandler {
    hce: Arc<dyn NfcHce>,
    cc_file_content: Vec<u8>,
    ndef_file_content: Vec<u8>,
    state: Mutex<State>,
}

struct State {
    message_read: bool,
    current_file: Option<File>,

    // marks failed session (one in which engagement cannot happen anymore)
    failure_sender: Option<oneshot::Sender<NfcError>>,
    failure_receiver: Option<oneshot::Receiver<NfcError>>,
}

#[derive(PartialEq)]
enum File {
    CapabilityContainer,
    NDEFMessage,
}

impl NfcStaticHandoverHandler {
    pub(crate) fn new(hce: Arc<dyn NfcHce>, ndef_file_content: &[u8]) -> Result<Self, NfcError> {
        let ndef_length = ndef_file_content.len();
        if ndef_length > 0xFFFF {
            return Err(NfcError::Unknown {
                reason: format!("NDEF file content too large: {ndef_length}"),
            });
        }

        let len = ndef_length as u16;
        let mut data = len.to_be_bytes().to_vec();
        data.extend(ndef_file_content);

        let (failure_sender, failure_receiver) = oneshot::channel();

        Ok(Self {
            hce,
            cc_file_content: capability_container_content(),
            ndef_file_content: data,
            state: Mutex::new(State {
                message_read: false,
                current_file: None,
                failure_sender: Some(failure_sender),
                failure_receiver: Some(failure_receiver),
            }),
        })
    }

    /// gives information whether a NFC scanner read the NDEF message or not
    pub(crate) fn message_read(&self) -> Result<bool, NfcError> {
        let state = self.state.lock().map_err(|e| NfcError::Unknown {
            reason: format!("Failed to aquire lock: {e}"),
        })?;
        Ok(state.message_read)
    }

    /// awaitable marking session failure
    pub(crate) fn session_failure(&self) -> Option<oneshot::Receiver<NfcError>> {
        self.with_lock(|state| Ok(state.failure_receiver.take()), None)
    }

    fn with_lock<R>(&self, f: impl FnOnce(&mut State) -> anyhow::Result<R>, fallback: R) -> R {
        match self.state.lock() {
            Ok(mut state) => match f(&mut state) {
                Ok(result) => result,
                Err(err) => {
                    tracing::warn!("Failed to handle command: {err}");
                    fallback
                }
            },
            Err(err) => {
                tracing::error!("Failed to aquire lock: {err}");
                fallback
            }
        }
    }
}

const RESPONSE_STATUS_SUCCESS: [u8; 2] = [0x90, 0x00];
const RESPONSE_STATUS_ERROR_FILE_OR_APPLICATION_NOT_FOUND: [u8; 2] = [0x6a, 0x82];
const RESPONSE_STATUS_ERROR_NO_PRECISE_DIAGNOSIS: [u8; 2] = [0x6f, 0x00];

/// Application ID of the Type 4 Tag NDEF application
const ENGAGEMENT_APPLICATION_ID: [u8; 7] = [0xd2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01];

const CAPABILITY_CONTAINER_FILE_ID: FileId = [0xe1, 0x03];
const NDEF_FILE_ID: FileId = [0xe1, 0x04];

#[async_trait::async_trait]
impl NfcHceHandler for NfcStaticHandoverHandler {
    fn handle_command(&self, apdu: Vec<u8>) -> Vec<u8> {
        self.with_lock(
            move |state| Ok(handle_apdu_command(apdu, state, self)?.into()),
            RESPONSE_STATUS_ERROR_NO_PRECISE_DIAGNOSIS.to_vec(),
        )
    }

    async fn on_scanner_disconnected(&self) {
        tracing::debug!("NFC scanner disconnected");
        let message_read = self.with_lock(
            |state| {
                state.current_file = None;
                Ok(state.message_read)
            },
            false,
        );

        if message_read && let Err(err) = self.hce.stop_hosting(true).await {
            tracing::warn!("Failed to stop hosting: {err}");
        }
    }

    async fn on_session_stopped(&self, reason: NfcError) {
        self.with_lock(
            |state| {
                let message_read = state.message_read;
                tracing::debug!(
                    "NFC session stopped, message_read: {message_read}, reason: {reason}"
                );

                // in case the session is cancelled by the system (iOS timeout, app put to background, ...)
                // or by user via system overlay (iOS) we should fail the proof flow
                if !message_read
                    && let Some(failure_sender) = state.failure_sender.take()
                    && let Err(err) = failure_sender.send(reason)
                {
                    tracing::debug!("Failed to signal failure: {err}");
                }

                Ok(())
            },
            (),
        );
    }
}

fn handle_apdu_command(
    command: Vec<u8>,
    state: &mut State,
    handler: &NfcStaticHandoverHandler,
) -> anyhow::Result<Response> {
    let command: KnownCommand = command.try_into()?;

    Ok(match command {
        KnownCommand::SelectApplication { application_id } => {
            if application_id != ENGAGEMENT_APPLICATION_ID {
                tracing::warn!("Invalid application selected: {application_id:?}");
                RESPONSE_STATUS_ERROR_FILE_OR_APPLICATION_NOT_FOUND.into()
            } else {
                state.current_file = None;
                RESPONSE_STATUS_SUCCESS.into()
            }
        }
        KnownCommand::SelectFile { file_id } => match file_id {
            CAPABILITY_CONTAINER_FILE_ID => {
                state.current_file = Some(File::CapabilityContainer);
                RESPONSE_STATUS_SUCCESS.into()
            }
            NDEF_FILE_ID => {
                state.current_file = Some(File::NDEFMessage);
                RESPONSE_STATUS_SUCCESS.into()
            }
            _ => {
                tracing::warn!("Invalid file selected: {file_id:?}");
                RESPONSE_STATUS_ERROR_FILE_OR_APPLICATION_NOT_FOUND.into()
            }
        },
        KnownCommand::ReadBinary { offset, length } => {
            let Some(file) = &state.current_file else {
                bail!("No file selected");
            };

            let content = match file {
                File::CapabilityContainer => &handler.cc_file_content,
                File::NDEFMessage => &handler.ndef_file_content,
            };

            let start = offset as usize;
            let end = start + length;
            if end > content.len() {
                bail!("Index out of bounds: offset:{offset}, lenght:{length}");
            }

            if file == &File::NDEFMessage && end == content.len() {
                state.message_read = true;
            }

            let mut response: Response = RESPONSE_STATUS_SUCCESS.into();
            response.payload = content[start..end].to_vec();
            response
        }
        KnownCommand::Other(command) => {
            bail!("Unknown command: {command:?}");
        }
    })
}

// these could be probably bigger, but since we are not sure on which devices are we running,
// let's stick to these minimal broadly supported values
const MAX_C_APDU: u16 = 255;
const MAX_R_APDU: u16 = 256;
const MAX_NDEF_SIZE: u16 = 0xFFFE;

fn capability_container_content() -> Vec<u8> {
    let mut result = vec![
        0x00, 0x0f, // CCLEN, length of the CC file (15 bytes)
        0x20, // Mapping Version 2.0
    ];
    result.extend(MAX_R_APDU.to_be_bytes());
    result.extend(MAX_C_APDU.to_be_bytes());
    result.extend(&[
        0x04, // T field of the NDEF File Control TLV
        0x06, // L field of the NDEF File Control TLV
    ]);
    result.extend(NDEF_FILE_ID);
    result.extend(MAX_NDEF_SIZE.to_be_bytes());
    result.extend(&[
        0x00, // Read access without any security
        0xFF, // no Write access (read-only)
    ]);
    result
}

#[cfg(test)]
mod tests {
    use mockall::predicate::eq;
    use similar_asserts::assert_eq;

    use super::*;
    use crate::proto::nfc::hce::MockNfcHce;

    #[test]
    fn test_capability_container_content() {
        let content = capability_container_content();
        assert_eq!(content.len(), 15);
        assert_eq!(
            content,
            &[
                0x00, 0x0f, 0x20, 0x01, 0x00, 0x00, 0xff, 0x04, 0x06, 0xe1, 0x04, 0xff, 0xfe, 0x00,
                0xff,
            ]
        );
    }

    #[test]
    fn test_static_handover_handler_no_contact() {
        let handler =
            NfcStaticHandoverHandler::new(Arc::new(MockNfcHce::new()), &[0x01, 0x02]).unwrap();
        assert_eq!(handler.message_read().unwrap(), false);
    }

    #[tokio::test]
    async fn test_static_handover_handler_regular_flow() {
        let mut hce = MockNfcHce::new();
        hce.expect_stop_hosting()
            .once()
            .with(eq(true))
            .returning(|_| Ok(()));

        let ndef_file_content = vec![0x01, 0x02, 0x03];
        let handler = NfcStaticHandoverHandler::new(Arc::new(hce), &ndef_file_content).unwrap();

        let run_command = |command: KnownCommand| -> Response {
            handler
                .handle_command(command.try_into().unwrap())
                .try_into()
                .unwrap()
        };

        assert_eq!(
            run_command(KnownCommand::SelectApplication {
                application_id: ENGAGEMENT_APPLICATION_ID.to_vec()
            }),
            RESPONSE_STATUS_SUCCESS.into()
        );

        assert_eq!(
            run_command(KnownCommand::SelectFile {
                file_id: CAPABILITY_CONTAINER_FILE_ID
            }),
            RESPONSE_STATUS_SUCCESS.into()
        );

        assert_eq!(
            run_command(KnownCommand::ReadBinary {
                offset: 0,
                length: 15,
            }),
            Response {
                payload: capability_container_content(),
                sw1: RESPONSE_STATUS_SUCCESS[0],
                sw2: RESPONSE_STATUS_SUCCESS[1]
            }
        );

        assert_eq!(
            run_command(KnownCommand::SelectFile {
                file_id: NDEF_FILE_ID
            }),
            RESPONSE_STATUS_SUCCESS.into()
        );

        assert_eq!(
            run_command(KnownCommand::ReadBinary {
                offset: 0,
                length: 2,
            }),
            Response {
                payload: vec![0x00, 0x03],
                sw1: RESPONSE_STATUS_SUCCESS[0],
                sw2: RESPONSE_STATUS_SUCCESS[1]
            }
        );

        assert_eq!(
            run_command(KnownCommand::ReadBinary {
                offset: 2,
                length: 3,
            }),
            Response {
                payload: ndef_file_content,
                sw1: RESPONSE_STATUS_SUCCESS[0],
                sw2: RESPONSE_STATUS_SUCCESS[1]
            }
        );

        assert_eq!(handler.message_read().unwrap(), true);

        handler.on_scanner_disconnected().await;
    }
}
