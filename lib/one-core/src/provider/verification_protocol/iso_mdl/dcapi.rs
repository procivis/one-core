use serde::{Deserialize, Serialize};
use shared_types::KeyId;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct MdocDcApiHolderInteractionData {
    pub device_request_bytes: Vec<u8>,
    pub session_transcript_bytes: Vec<u8>,
    pub encryption_info: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MdocDcApiVerifierInteractionData {
    pub encryption_key: KeyId,
    pub session_transcript_bytes: Vec<u8>,
}
