use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use super::common::{build_proof, hash_entry, make_keyref, resolution_error};
use super::{DidWebvh, LogEntry, LogParameters};
use crate::provider::did_method::error::DidMethodError;
use crate::provider::did_method::{DidKeys, DidUpdate};

pub(super) async fn deactivate(
    method: &DidWebvh,
    keys: DidKeys,
    log: Option<String>,
) -> Result<DidUpdate, DidMethodError> {
    let log = log.ok_or_else(|| DidMethodError::CouldNotDeactivate("Missing log".to_string()))?;
    let verified = method.verify_log(&log, None).await?;
    if verified.deactivated {
        return Err(DidMethodError::Deactivated);
    }
    let stored_keys = keys
        .update_keys
        .ok_or_else(|| DidMethodError::CouldNotDeactivate("Missing update keys".to_string()))?;
    let mut signer = None;
    for key in &stored_keys {
        let key_ref = make_keyref(key, method.key_provider.as_ref())?;
        if verified.active_keys.contains(&key_ref.multibase) {
            signer = Some(key_ref);
            break;
        }
    }
    let signer = signer.ok_or_else(|| {
        DidMethodError::CouldNotDeactivate("No authorized update key is available".to_string())
    })?;
    let previous = verified
        .entries
        .last()
        .ok_or_else(|| resolution_error("Empty DID log"))?;
    let previous_time = OffsetDateTime::parse(&previous.version_time, &Rfc3339)
        .map_err(|e| resolution_error(format!("Invalid versionTime: {e}")))?;
    let now = std::cmp::max(
        crate::clock::now_utc(),
        previous_time + Duration::nanoseconds(1),
    );
    let mut entry = LogEntry {
        version_id: previous.version_id.clone(),
        version_time: now
            .format(&Rfc3339)
            .map_err(|e| DidMethodError::CouldNotDeactivate(e.to_string()))?,
        parameters: LogParameters {
            update_keys: Some(vec![]),
            deactivated: Some(true),
            ..Default::default()
        },
        state: previous.state.clone(),
        proof: vec![],
    };
    let hash = hash_entry(&serde_json::to_value(&entry)?, &previous.version_id)?;
    entry.version_id = format!("{}-{hash}", verified.entries.len() + 1);
    entry.proof.push(build_proof(&entry, &signer, now).await?);
    let line = serde_json::to_string(&entry)?;
    Ok(DidUpdate {
        deactivated: Some(true),
        log: Some(format!("{}\n{line}\n", log.trim_end_matches(['\r', '\n']))),
    })
}
