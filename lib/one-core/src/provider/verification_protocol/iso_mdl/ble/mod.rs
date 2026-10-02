use std::iter;
use std::sync::LazyLock;

use serde_repr::{Deserialize_repr, Serialize_repr};
use uuid::Uuid;

use crate::provider::verification_protocol::error::VerificationProtocolError;

mod central;
mod central_client_mode;
pub(super) mod common;
pub(crate) mod holder;
mod peripheral;
mod peripheral_server_mode;
pub(crate) mod verifier;

/// Shared BleWaiter flowId for both verifier and holder
pub(super) static ISO_MDL_FLOW: LazyLock<Uuid> = LazyLock::new(Uuid::new_v4);

/// BLE State commands according to ISO 18013-5, Table 13
#[derive(Debug, Serialize_repr, Deserialize_repr, PartialEq)]
#[repr(u8)]
enum Command {
    Start = 1,
    End = 2,
}

impl TryFrom<Vec<u8>> for Command {
    type Error = VerificationProtocolError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        match value.as_slice() {
            [1] => Ok(Self::Start),
            [2] => Ok(Self::End),
            value => Err(VerificationProtocolError::Failed(format!(
                "Unknown State command: {value:?}"
            ))),
        }
    }
}

/// A single partial message sent over BLE
/// ISO 18013-5, 8.3.3.1.1.6
#[derive(Debug, Clone)]
enum Chunk {
    Next(Vec<u8>),
    Last(Vec<u8>),
}

impl TryFrom<Vec<u8>> for Chunk {
    type Error = VerificationProtocolError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        match value.as_slice() {
            [0, tail @ ..] => Ok(Self::Last(tail.to_vec())),
            [1, tail @ ..] => Ok(Self::Next(tail.to_vec())),
            chunk => Err(VerificationProtocolError::Failed(format!(
                "Invalid BLE chunk, length: {}, firstByte: {:?}",
                chunk.len(),
                chunk.first()
            ))),
        }
    }
}

impl From<Chunk> for Vec<u8> {
    fn from(value: Chunk) -> Self {
        match value {
            Chunk::Last(v) => iter::once(0).chain(v).collect(),
            Chunk::Next(v) => iter::once(1).chain(v).collect(),
        }
    }
}

fn split_into_chunks(
    session_message: Vec<u8>,
    max_payload_size: usize,
) -> Result<Vec<Vec<u8>>, VerificationProtocolError> {
    let mut chunks = session_message.chunks(
        // lower size by 1 (for the prepended chunk header)
        max_payload_size - 1,
    );

    tracing::debug!(
        "About to send {} chunks, max_payload_size: {max_payload_size}",
        chunks.len()
    );

    let last = Chunk::Last(
        chunks
            .next_back()
            .ok_or(VerificationProtocolError::Failed("no chunks".to_string()))?
            .to_vec(),
    );

    Ok(chunks
        .map(|slice| Chunk::Next(slice.to_vec()))
        .chain(iter::once(last))
        .map(Into::into)
        .collect())
}
