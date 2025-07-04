use serde::Serialize;

use crate::config::core_config::FormatType;

#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentationFormatterCapabilities {
    pub supported_credential_formats: Vec<FormatType>,
}

pub struct CredentialToPresent {
    pub raw_credential: String,
    pub credential_format: FormatType,
}
