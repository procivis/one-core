use std::io::BufRead;

use shared_types::DidValue;

use super::DidWebvh;
use super::common::{normalize_document, resolution_error};
use super::identifier::validate_did_parts;
use crate::provider::did_method::dto::DidDocumentDTO;
use crate::provider::did_method::error::DidMethodError;
use crate::provider::did_method::model::DidDocument;

pub(super) async fn resolve(
    method: &DidWebvh,
    did: &DidValue,
) -> Result<DidDocument, DidMethodError> {
    let mut url = validate_did_parts(did.as_str())?;
    if method.params.resolve_to_insecure_http {
        url.set_scheme("http")
            .map_err(|_| resolution_error("Invalid URL scheme"))?;
    }
    let response = method
        .client
        .get(url.as_str())
        // the spec mandates `text/jsonl`, but some deployments (e.g. swiyu) serve
        // `application/jsonl+json`; the response media type is not checked either way
        .header("Accept", "text/jsonl, application/jsonl+json")
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| resolution_error(format!("Failed retrieving DID log: {e}")))?;
    let log = response
        .body
        .lines()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| resolution_error(format!("Invalid DID log: {e}")))?
        .join("\n");
    let verified = method.verify_log(&log, Some(did)).await?;
    if verified.deactivated {
        return Err(DidMethodError::Deactivated);
    }
    let state = verified
        .entries
        .last()
        .ok_or_else(|| resolution_error("Empty DID log"))?
        .state
        .clone();
    let state = normalize_document(state, method.key_algorithm_provider.as_ref())?;
    let document: DidDocumentDTO = serde_json::from_value(state)
        .map_err(|e| resolution_error(format!("Invalid DID document: {e}")))?;
    Ok(document.into())
}
