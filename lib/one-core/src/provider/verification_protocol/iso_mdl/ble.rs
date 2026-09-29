use std::iter;
use std::sync::LazyLock;

use uuid::Uuid;

use crate::provider::verification_protocol::error::VerificationProtocolError;

// BLE peripheral server mode characteristics
pub(crate) const STATE: &str = "00000001-A123-48CE-896B-4C76973373E6";
pub(crate) const CLIENT_2_SERVER: &str = "00000002-A123-48CE-896B-4C76973373E6";
pub(crate) const SERVER_2_CLIENT: &str = "00000003-A123-48CE-896B-4C76973373E6";

// Shared BleWaiter flowId for both verifier and holder
pub(crate) static ISO_MDL_FLOW: LazyLock<Uuid> = LazyLock::new(Uuid::new_v4);

/// A single partial message sent over BLE
/// ISO 18013-5, 8.3.3.1.1.6
#[derive(Debug, Clone)]
pub(crate) enum Chunk {
    Next(Vec<u8>),
    Last(Vec<u8>),
}

impl TryFrom<Vec<u8>> for Chunk {
    type Error = VerificationProtocolError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        match value.as_slice() {
            [0, tail @ ..] => Ok(Self::Last(tail.to_vec())),
            [1, tail @ ..] => Ok(Self::Next(tail.to_vec())),
            _ => Err(VerificationProtocolError::Failed(
                "Invalid BLE chunk".to_string(),
            )),
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

pub(super) fn split_into_chunks(
    session_message: Vec<u8>,
    mtu_size: usize,
) -> Result<Vec<Vec<u8>>, VerificationProtocolError> {
    let mut chunks = session_message.chunks(mtu_size - 1);

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
