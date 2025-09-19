// NFC static handover handling according to ISO 18013-5 (mDL) and NFC Forum, Connection Handover (CH) Technical Specification, Version 1.5

use std::sync::Mutex;

use anyhow::bail;

use crate::provider::nfc::NfcError;
use crate::provider::nfc::apdu::Response;
use crate::provider::nfc::command::KnownCommand;
use crate::provider::nfc::hce::NfcHceHandler;

/// Wraps NFC Static handover functionality
pub(crate) struct NfcStaticHandoverHandler {
    ndef_file_content: Vec<u8>,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    message_read: bool,
    current_file_content: Option<Vec<u8>>,
}

impl NfcStaticHandoverHandler {
    pub(crate) fn new(ndef_file_content: Vec<u8>) -> Result<Self, NfcError> {
        if ndef_file_content.len() > 0xFFFF {
            return Err(NfcError::Unknown {
                reason: format!("NDEF file content too large: {}", ndef_file_content.len()),
            });
        }

        Ok(Self {
            ndef_file_content,
            state: Default::default(),
        })
    }

    /// gives information whether a NFC scanner read the NDEF message or not
    pub(crate) fn message_read(&self) -> Result<bool, NfcError> {
        let state = self.state.lock().map_err(|e| NfcError::Unknown {
            reason: format!("Failed to aquire lock: {e}"),
        })?;
        Ok(state.message_read)
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

const CAPABILITY_CONTAINER_FILE_ID: [u8; 2] = [0xe1, 0x03];
const NDEF_FILE_ID: [u8; 2] = [0xe1, 0x04];

impl NfcHceHandler for NfcStaticHandoverHandler {
    fn handle_command(&self, apdu: Vec<u8>) -> Vec<u8> {
        self.with_lock(
            move |state| Ok(handle_apdu_command(apdu, state, &self.ndef_file_content)?.into()),
            RESPONSE_STATUS_ERROR_NO_PRECISE_DIAGNOSIS.to_vec(),
        )
    }

    fn on_disconnected(&self) {
        self.with_lock(
            |state| {
                state.current_file_content = None;
                Ok(())
            },
            (),
        )
    }
}

fn handle_apdu_command(
    command: Vec<u8>,
    state: &mut State,
    ndef_file_content: &[u8],
) -> anyhow::Result<Response> {
    let command: KnownCommand = command.try_into()?;

    Ok(match command {
        KnownCommand::SelectApplication { application_id } => {
            if application_id != ENGAGEMENT_APPLICATION_ID {
                tracing::warn!("Invalid application selected: {application_id:?}");
                RESPONSE_STATUS_ERROR_FILE_OR_APPLICATION_NOT_FOUND.into()
            } else {
                state.current_file_content = None;
                RESPONSE_STATUS_SUCCESS.into()
            }
        }
        KnownCommand::SelectFile { file_id } => match file_id {
            CAPABILITY_CONTAINER_FILE_ID => {
                state.current_file_content = Some(capability_container_content());
                RESPONSE_STATUS_SUCCESS.into()
            }
            NDEF_FILE_ID => {
                let len = ndef_file_content.len() as u16;
                let mut data = len.to_be_bytes().to_vec();
                data.extend(ndef_file_content);

                state.current_file_content = Some(data);
                state.message_read = true;
                RESPONSE_STATUS_SUCCESS.into()
            }
            _ => {
                tracing::warn!("Invalid file selected: {file_id:?}");
                RESPONSE_STATUS_ERROR_FILE_OR_APPLICATION_NOT_FOUND.into()
            }
        },
        KnownCommand::ReadBinary { offset, length } => {
            let Some(content) = &state.current_file_content else {
                bail!("No file selected");
            };

            let start = offset as usize;
            let end = start + length;
            if end > content.len() {
                bail!("Index out of bounds: offset:{offset}, lenght:{length}");
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
    use similar_asserts::assert_eq;

    use super::*;

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
        let handler = NfcStaticHandoverHandler::new(vec![0x01, 0x02]).unwrap();
        assert_eq!(handler.message_read().unwrap(), false);
    }

    #[test]
    fn test_static_handover_handler_regular_flow() {
        let ndef_file_content = vec![0x01, 0x02, 0x03];
        let handler = NfcStaticHandoverHandler::new(ndef_file_content.clone()).unwrap();

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
    }
}
