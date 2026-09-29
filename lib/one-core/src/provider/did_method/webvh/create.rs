use std::collections::HashSet;

use serde::Deserialize;
use serde_json::{Value, json};
use shared_types::{DidId, DidValue};
use time::format_description::well_known::Rfc3339;
use url::Url;

use super::common::{build_proof, hash_entry, hash_json, make_keyref, now_utc, without_proof};
use super::identifier::validate_did_parts;
use super::mapper::url_to_did;
use super::{DidWebvh, LogEntry, LogParameters, METHOD, PREFIX, SCID_PLACEHOLDER};
use crate::config::core_config::KeyAlgorithmType;
use crate::error::ContextWithErrorCode;
use crate::provider::did_method::error::DidMethodError;
use crate::provider::did_method::{DidCreated, DidKeys};
use crate::provider::key_storage::provider::KeyProvider;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DidCreateParams {
    external_hosting_url: Url,
}

fn domain(
    method: &DidWebvh,
    id: DidId,
    external_hosting_url: Option<Url>,
) -> Result<String, DidMethodError> {
    if let Some(url) = external_hosting_url {
        return url_to_did(url);
    }
    let base_url = method
        .core_base_url
        .as_ref()
        .ok_or_else(|| DidMethodError::InitializationError("Missing core base url".to_string()))?;
    let mut domain = url_to_did(Url::parse(base_url)?)?;
    domain.push_str(":ssi:did-webvh:v1:");
    domain.push_str(&id.to_string());
    Ok(domain)
}

pub(super) async fn create(
    method: &DidWebvh,
    id: DidId,
    params: &Option<Value>,
    keys: DidKeys,
) -> Result<DidCreated, DidMethodError> {
    let update_keys = keys
        .update_keys
        .as_deref()
        .ok_or_else(|| DidMethodError::CreationError("Missing update keys".to_string()))?;
    let active = update_keys
        .first()
        .ok_or_else(|| DidMethodError::CreationError("Missing update keys".to_string()))?;
    if update_keys.len() != 1 {
        return Err(DidMethodError::CreationError(
            "Exactly one update key is supported".to_string(),
        ));
    }
    for key in update_keys {
        if key.key_type != KeyAlgorithmType::Eddsa.as_ref() {
            return Err(DidMethodError::CreationError(
                "Update keys must be EdDSA".to_string(),
            ));
        }
    }
    let external = params
        .as_ref()
        .filter(|params| params.as_object().is_some_and(|obj| !obj.is_empty()))
        .map(|params| {
            DidCreateParams::deserialize(params)
                .map(|parsed| parsed.external_hosting_url)
                .map_err(|err| DidMethodError::CreationError(format!("Invalid params: {err}")))
        })
        .transpose()?;
    let domain = domain(method, id, external)?;
    let placeholder_did = format!("{PREFIX}{SCID_PLACEHOLDER}:{domain}");
    validate_did_parts(&format!(
        "{PREFIX}QmRXEKqsStiagD4DBZG1gwrtpoNfxSUwHd8vxQMBytR5zW:{domain}"
    ))?;
    let active_ref = make_keyref(active, method.key_provider.as_ref())?;
    let document = create_document(&placeholder_did, &keys, method.key_provider.as_ref())?;
    let now = now_utc()?;
    let mut entry = LogEntry {
        version_id: SCID_PLACEHOLDER.to_string(),
        version_time: now
            .format(&Rfc3339)
            .map_err(|e| DidMethodError::CreationError(e.to_string()))?,
        parameters: LogParameters {
            method: Some(METHOD.to_string()),
            scid: Some(SCID_PLACEHOLDER.to_string()),
            update_keys: Some(vec![active_ref.multibase.clone()]),
            next_key_hashes: Some(vec![]),
            portable: Some(false),
            witness: Some(Default::default()),
            watchers: Some(vec![]),
            ..Default::default()
        },
        state: document,
        proof: vec![],
    };
    let scid = hash_json(&without_proof(serde_json::to_value(&entry)?)?)?;
    let replaced = serde_json::to_string(&entry)?.replace(SCID_PLACEHOLDER, &scid);
    entry = serde_json::from_str(&replaced)?;
    let hash = hash_entry(&serde_json::to_value(&entry)?, &scid)?;
    entry.version_id = format!("1-{hash}");
    entry
        .proof
        .push(build_proof(&entry, &active_ref, now).await?);
    let did: DidValue = entry
        .state
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| DidMethodError::CreationError("Missing DID".to_string()))?
        .parse()?;
    Ok(DidCreated {
        did,
        log: Some(format!("{}\n", serde_json::to_string(&entry)?)),
    })
}

fn create_document(
    did: &str,
    keys: &DidKeys,
    provider: &dyn KeyProvider,
) -> Result<Value, DidMethodError> {
    let mut verification_methods = vec![];
    let mut seen = HashSet::new();
    let mut document = serde_json::Map::new();
    document.insert(
        "@context".to_string(),
        json!([
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/jwk/v1"
        ]),
    );
    document.insert("id".to_string(), json!(did));
    for (name, role_keys) in [
        ("authentication", &keys.authentication),
        ("assertionMethod", &keys.assertion_method),
        ("keyAgreement", &keys.key_agreement),
        ("capabilityInvocation", &keys.capability_invocation),
        ("capabilityDelegation", &keys.capability_delegation),
    ] {
        let mut refs = vec![];
        for key in role_keys {
            let key_id = format!("key-{}", key.id);
            let id = format!("{did}#{key_id}");
            if seen.insert(id.clone()) {
                let handle = make_keyref(key, provider)?.handle;
                let mut jwk = handle
                    .public_key_as_jwk()
                    .error_while("getting public JWK")?;
                jwk.set_kid(key_id);
                verification_methods.push(json!({
                    "id": id,
                    "type": "JsonWebKey2020",
                    "controller": did,
                    "publicKeyJwk": jwk,
                }));
            }
            refs.push(id);
        }
        if !refs.is_empty() {
            document.insert(name.to_string(), json!(refs));
        }
    }
    if !verification_methods.is_empty() {
        document.insert(
            "verificationMethod".to_string(),
            json!(verification_methods),
        );
    }
    Ok(Value::Object(document))
}
