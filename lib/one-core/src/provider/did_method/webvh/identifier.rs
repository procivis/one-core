use std::net::IpAddr;

use shared_types::DidValue;
use url::Url;

use super::PREFIX;
use super::common::{check_multihash, resolution_error};
use crate::provider::did_method::error::DidMethodError;

/// Extract the SCID and validate the rest of a bare method-specific identifier.
/// https://identity.foundation/didwebvh/v1.0/#method-specific-identifier
pub(super) fn parse_did(did: &DidValue) -> Result<(&str, Url), DidMethodError> {
    let suffix = did
        .as_str()
        .strip_prefix(PREFIX)
        .ok_or_else(|| resolution_error("Expected did:webvh"))?;
    let (scid, _) = suffix
        .split_once(':')
        .ok_or_else(|| resolution_error("Missing DID domain"))?;
    check_multihash(scid)?;
    Ok((scid, validate_did_parts(did.as_str())?))
}

/// Validate a bare DID and locate its published `did.jsonl` log.
/// https://identity.foundation/didwebvh/v1.0/#method-specific-identifier
/// https://identity.foundation/didwebvh/v1.0/#the-did-to-https-transformation
pub(super) fn validate_did_parts(did: &str) -> Result<Url, DidMethodError> {
    // The method-specific ID starts with a 46-character base58btc SCID, then a domain.
    // https://identity.foundation/didwebvh/v1.0/#method-specific-identifier
    let suffix = did
        .strip_prefix(PREFIX)
        .ok_or_else(|| resolution_error("Expected did:webvh"))?;
    let mut parts = suffix.split(':');
    let scid = parts
        .next()
        .ok_or_else(|| resolution_error("Missing SCID"))?;
    check_multihash(scid)?;
    let domain_part = parts
        .next()
        .ok_or_else(|| resolution_error("Missing DID domain"))?;
    // Decode the domain once; a port is separated by one percent-encoded colon.
    // https://identity.foundation/didwebvh/v1.0/#method-specific-identifier
    let decoded_domain = urlencoding::decode(domain_part)
        .map_err(|e| resolution_error(format!("Invalid domain encoding: {e}")))?;
    let (host, port) = if let Some((host, port)) = decoded_domain.split_once(':') {
        if !(domain_part.contains("%3A") || domain_part.contains("%3a")) || port.contains(':') {
            return Err(resolution_error("Invalid domain port encoding"));
        }
        let port: u16 = port
            .parse()
            .map_err(|_| resolution_error("Invalid DID port"))?;
        if port == 0 {
            return Err(resolution_error("Invalid DID port"));
        }
        (host, Some(port))
    } else {
        (decoded_domain.as_ref(), None)
    };
    // Require a DNS name after IDNA processing and reject numeric IP hosts,
    // including names that a URL parser normalizes into an IP address.
    // https://identity.foundation/didwebvh/v1.0/#method-specific-identifier
    if !host.contains('.')
        || host.contains('%')
        || host.parse::<IpAddr>().is_ok()
        || host.ends_with('.')
    {
        return Err(resolution_error("DID domain must be a DNS name"));
    }
    let mut url = Url::parse(&format!("https://{host}"))
        .map_err(|e| resolution_error(format!("Invalid DID domain: {e}")))?;
    let domain = url
        .domain()
        .ok_or_else(|| resolution_error("DID domain must be a DNS name"))?;
    if url.host_str().is_some_and(|h| h.parse::<IpAddr>().is_ok())
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || domain.len() > 253
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .next()
                    .is_some_and(|b| b.is_ascii_alphanumeric())
                || !label
                    .bytes()
                    .last()
                    .is_some_and(|b| b.is_ascii_alphanumeric())
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(resolution_error("DID domain must be a DNS name"));
    }
    if let Some(port) = port {
        url.set_port(Some(port))
            .map_err(|_| resolution_error("Invalid DID port"))?;
    }
    // Colons after the domain delimit deployment path segments, not DID URL paths.
    // Decode once and reject unsafe or empty segments before re-encoding for HTTPS.
    // https://identity.foundation/didwebvh/v1.0/#the-did-to-https-transformation
    let mut path = Vec::new();
    for segment in parts {
        let decoded = urlencoding::decode(segment)
            .map_err(|e| resolution_error(format!("Invalid path encoding: {e}")))?;
        if decoded.is_empty()
            || decoded == "."
            || decoded == ".."
            || decoded.contains(['/', '\\', '\0'])
            || decoded.trim() != decoded
        {
            return Err(resolution_error("Invalid DID deployment path"));
        }
        path.push(urlencoding::encode(&decoded).into_owned());
    }
    // The log lives under .well-known only when there is no deployment path.
    // https://identity.foundation/didwebvh/v1.0/#the-did-to-https-transformation
    if path.is_empty() {
        url.set_path("/.well-known/did.jsonl");
    } else {
        url.set_path(&format!("/{}/did.jsonl", path.join("/")));
    }
    Ok(url)
}
