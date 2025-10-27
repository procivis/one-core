use ct_codecs::{Base64UrlSafeNoPadding, Encoder};

use crate::provider::credential_formatter::error::FormatterError;

pub fn bin_to_b64url_string(bin: &[u8]) -> Result<String, FormatterError> {
    Base64UrlSafeNoPadding::encode_to_string(bin)
        .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))
}

pub fn string_to_b64url_string(string: &str) -> Result<String, FormatterError> {
    Base64UrlSafeNoPadding::encode_to_string(string)
        .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))
}
