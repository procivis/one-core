use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct MdocDcApiHolderInteractionData {
    pub device_request_bytes: Vec<u8>,
    pub session_transcript_bytes: Vec<u8>,
    pub encryption_info: String,
}
