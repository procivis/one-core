use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use super::common::{build_proof, hash_entry, make_keyref};
use super::create::create_document;
use super::{DidWebvh, KeyRef, LogEntry, LogParameters, VerifiedLog};
use crate::config::core_config::KeyAlgorithmType;
use crate::provider::did_method::error::DidMethodError;
use crate::provider::did_method::{DidKeys, DidUpdate};

/// Append an authorized key replacement per did:webvh 1.0.
/// https://identity.foundation/didwebvh/v1.0/#update-rotate
pub(super) async fn update(
    method: &DidWebvh,
    keys: DidKeys,
    new_keys: DidKeys,
    log: Option<String>,
) -> Result<DidUpdate, DidMethodError> {
    let log = log.ok_or_else(|| DidMethodError::CouldNotUpdate("Missing log".to_string()))?;
    let verified = verify_log_for_update(method, &log).await?;
    let signer = select_authorized_signer(method, &keys, &verified.active_keys)?;
    let parameters = build_update_parameters(method, &new_keys, &verified.active_keys)?;
    let entry =
        build_signed_update_entry(method, &verified, &new_keys, &signer, parameters).await?;
    let line = serde_json::to_string(&entry)?;
    warn_if_resolution_limit_exceeded(method, &entry, verified.entries.len() + 1);
    Ok(DidUpdate {
        deactivated: None,
        log: Some(format!("{}\n{line}\n", log.trim_end_matches(['\r', '\n']))),
    })
}

async fn verify_log_for_update(
    method: &DidWebvh,
    log: &str,
) -> Result<VerifiedLog, DidMethodError> {
    let verified = method.verify_stored_log(log, None).await?;
    if verified.deactivated {
        return Err(DidMethodError::Deactivated);
    }
    // This interface has no future-key commitments. Never silently disable or bypass
    // pre-rotation on an imported log, or reuse its revealed commitment keys.
    if !verified.next_key_hashes.is_empty() {
        return Err(DidMethodError::CouldNotUpdate(
            "Updating logs with active key pre-rotation is not supported".to_string(),
        ));
    }
    Ok(verified)
}

fn select_authorized_signer(
    method: &DidWebvh,
    keys: &DidKeys,
    active_keys: &[String],
) -> Result<KeyRef, DidMethodError> {
    for key in keys.update_keys.as_deref().unwrap_or_default() {
        let key_ref = make_keyref(key, method.key_provider.as_ref())?;
        if active_keys.contains(&key_ref.multibase) {
            return Ok(key_ref);
        }
    }
    Err(DidMethodError::CouldNotUpdate(
        "No authorized update key is available".to_string(),
    ))
}

fn build_update_parameters(
    method: &DidWebvh,
    new_keys: &DidKeys,
    active_keys: &[String],
) -> Result<LogParameters, DidMethodError> {
    let replacement_keys = new_keys.update_keys.as_deref().ok_or_else(|| {
        DidMethodError::CouldNotUpdate("Missing replacement update keys".to_string())
    })?;
    let [key] = replacement_keys else {
        return Err(DidMethodError::CouldNotUpdate(
            "Exactly one update key is supported".to_string(),
        ));
    };
    if key.key_type != KeyAlgorithmType::Eddsa.as_ref() {
        return Err(DidMethodError::UnsupportedKeyType(key.key_type.clone()));
    }
    let key_ref = make_keyref(key, method.key_provider.as_ref())?;
    // Unchanged parameters are omitted from the log and inherit their prior values.
    let replacement = vec![key_ref.multibase];
    Ok(LogParameters {
        update_keys: (active_keys != replacement).then_some(replacement),
        ..Default::default()
    })
}

async fn build_signed_update_entry(
    method: &DidWebvh,
    verified: &VerifiedLog,
    new_keys: &DidKeys,
    signer: &KeyRef,
    parameters: LogParameters,
) -> Result<LogEntry, DidMethodError> {
    let previous = verified
        .entries
        .last()
        .ok_or_else(|| DidMethodError::CouldNotUpdate("Empty DID log".to_string()))?;
    let previous_time = OffsetDateTime::parse(&previous.version_time, &Rfc3339)
        .map_err(|e| DidMethodError::CouldNotUpdate(format!("Invalid versionTime: {e}")))?;
    let now = std::cmp::max(
        crate::clock::now_utc(),
        previous_time + Duration::nanoseconds(1),
    );
    let mut entry = LogEntry {
        version_id: previous.version_id.clone(),
        version_time: now
            .format(&Rfc3339)
            .map_err(|e| DidMethodError::CouldNotUpdate(e.to_string()))?,
        parameters,
        state: update_document(method, previous.state.clone(), new_keys)?,
        proof: vec![],
    };
    let hash = hash_entry(&serde_json::to_value(&entry)?, &previous.version_id)?;
    entry.version_id = format!("{}-{hash}", verified.entries.len() + 1);
    entry.proof.push(build_proof(&entry, signer, now).await?);
    Ok(entry)
}

fn warn_if_resolution_limit_exceeded(method: &DidWebvh, entry: &LogEntry, entry_count: usize) {
    if let Some(limit) = method.params.max_did_log_entry_check
        && entry_count > limit as usize
    {
        tracing::warn!(
            did = ?entry.state.get("id"),
            entries = entry_count,
            max_did_log_entry_check = limit,
            "Updated DID log exceeds the configured resolution entry limit and cannot be resolved with this configuration"
        );
    }
}

fn update_document(
    method: &DidWebvh,
    mut state: Value,
    keys: &DidKeys,
) -> Result<Value, DidMethodError> {
    let did = state
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| DidMethodError::CouldNotUpdate("Missing state.id".to_string()))?;
    let replacement = create_document(did, keys, method.key_provider.as_ref(), false)?;
    let document = state.as_object_mut().ok_or_else(|| {
        DidMethodError::CouldNotUpdate("DID document must be an object".to_string())
    })?;
    for name in [
        "verificationMethod",
        "authentication",
        "assertionMethod",
        "keyAgreement",
        "capabilityInvocation",
        "capabilityDelegation",
    ] {
        if let Some(value) = replacement.get(name) {
            document.insert(name.to_string(), value.clone());
        } else {
            document.remove(name);
        }
    }
    // Preserve services, aliases, profile markers and custom contexts. Ensure the
    // contexts required by our JsonWebKey2020 verification methods are also present.
    let mut contexts = match document.remove("@context") {
        Some(Value::Array(contexts)) => contexts,
        Some(context) => vec![context],
        None => vec![],
    };
    if let Some(required) = replacement.get("@context").and_then(Value::as_array) {
        for context in required {
            if !contexts.contains(context) {
                contexts.push(context.clone());
            }
        }
    }
    document.insert("@context".to_string(), Value::Array(contexts));
    Ok(state)
}
