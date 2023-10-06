use crate::credential_formatter::FormatterError;

pub(super) fn json_from_decoded(decoded: Vec<u8>) -> Result<String, FormatterError> {
    let result = String::from_utf8(decoded)
        .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))?;
    Ok(result)
}
