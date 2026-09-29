use url::Url;

use crate::provider::did_method::error::DidMethodError;

/// Encode the hosting origin and path as method-specific DID components.
/// https://identity.foundation/didwebvh/v1.0/#the-did-to-https-transformation
pub(super) fn url_to_did(url: Url) -> Result<String, DidMethodError> {
    if url.scheme() != "https" && url.scheme() != "http" {
        return Err(DidMethodError::CreationError(
            "Hosting URL must use HTTP(S)".to_string(),
        ));
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(DidMethodError::CreationError(
            "Hosting URL has unsupported components".to_string(),
        ));
    }
    let host = url.domain().ok_or_else(|| {
        DidMethodError::CreationError("Hosting URL requires a domain".to_string())
    })?;
    let mut result = host.to_string();
    if let Some(port) = url.port() {
        result.push_str(&format!("%3A{port}"));
    }
    for segment in url
        .path_segments()
        .into_iter()
        .flatten()
        .filter(|s| !s.is_empty())
    {
        result.push(':');
        result.push_str(segment);
    }
    Ok(result)
}
