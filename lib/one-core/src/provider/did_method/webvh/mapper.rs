use url::Url;

use crate::provider::did_method::dto::DidDocumentDTO;
use crate::provider::did_method::error::DidMethodError;
use crate::provider::did_method::webvh::serialize::DidDocState;

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

impl TryFrom<super::deserialize::DidLogEntry> for super::serialize::DidLogEntry {
    type Error = DidMethodError;

    fn try_from(entry: super::deserialize::DidLogEntry) -> Result<Self, DidMethodError> {
        Ok(Self {
            version_id: entry.version_id,
            version_time: entry.version_time,
            parameters: entry.parameters,
            state: DidDocState {
                value: entry.state.value.document.try_into()?,
            },
            proof: entry.proof,
        })
    }
}

impl TryFrom<DidDocumentDTO> for super::serialize::DidDocument {
    type Error = DidMethodError;

    fn try_from(value: DidDocumentDTO) -> Result<Self, DidMethodError> {
        Ok(Self {
            context: serde_json::from_value(value.context).map_err(|err| {
                DidMethodError::MappingError(format!("failed to parse context: {err}"))
            })?,
            id: value.id.to_string(),
            verification_method: value.verification_method,
            authentication: value.authentication.unwrap_or_default(),
            assertion_method: value.assertion_method.unwrap_or_default(),
            key_agreement: value.key_agreement.unwrap_or_default(),
            capability_invocation: value.capability_invocation.unwrap_or_default(),
            capability_delegation: value.capability_delegation.unwrap_or_default(),
        })
    }
}
