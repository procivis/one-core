use crate::config::core_config::FormatType;

pub struct PresentationFormatterCapabilities {
    pub supported_credential_formats: Vec<FormatType>,
}

pub struct CredentialToPresent {
    pub raw_credential: String,
    pub credential_format: FormatType,
}
