#[derive(Clone, Debug)]
pub struct NfcScanRequestDTO {
    pub in_progress_message: Option<String>,
    pub failure_message: Option<String>,
    pub success_message: Option<String>,
}
