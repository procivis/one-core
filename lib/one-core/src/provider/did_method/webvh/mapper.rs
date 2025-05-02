use url::Url;

use crate::provider::did_method::error::DidMethodError;

pub(super) fn url_to_did(url: Url) -> Result<String, DidMethodError> {
    let mut domain = url
        .domain()
        .or(url.host_str())
        .ok_or_else(|| {
            DidMethodError::CouldNotCreate(
                "Invalid core base url: missing domain or host".to_string(),
            )
        })?
        .to_owned();

    if let Some(port) = url.port() {
        // percent encode `:`
        domain.push_str("%3A");
        domain.push_str(&port.to_string());
    }

    let path = url.path().trim_end_matches('/');
    if !path.is_empty() {
        domain.push_str(&path.replace("/", ":"));
    }
    Ok(domain)
}
