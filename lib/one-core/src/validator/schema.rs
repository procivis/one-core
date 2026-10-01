use url::Url;

use crate::error::{ErrorCode, ErrorCodeMixin};

#[derive(Debug, thiserror::Error)]
#[error("Schema importedSourceUrl must be a valid HTTP(S) URL")]
pub(crate) struct InvalidImportedSourceUrl;

impl ErrorCodeMixin for InvalidImportedSourceUrl {
    fn error_code(&self) -> ErrorCode {
        ErrorCode::BR_0512
    }
}

pub(crate) fn validate_imported_source_url(url: &str) -> Result<(), InvalidImportedSourceUrl> {
    let url = Url::parse(url).map_err(|_| InvalidImportedSourceUrl)?;
    if !matches!(url.scheme(), "http" | "https") || !url.has_host() {
        return Err(InvalidImportedSourceUrl);
    }
    Ok(())
}
