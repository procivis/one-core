use std::str::FromStr;

use DidMethodError::{Deactivated, ResolutionError};
use json_syntax::json;
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use shared_types::DidValue;
use time::OffsetDateTime;

use super::common::{DidLogParameters, canonicalized_hash, multihash_b58_encode};
use crate::model::did::KeyRole;
use crate::provider::credential_formatter::vcdm::VcdmProof;
use crate::provider::did_method::error::DidMethodError;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::did_method::webvh::Params;
use crate::provider::did_method::webvh::deserialize::{DidLogEntry, DidMethodVersion};
use crate::provider::key_algorithm::KeyAlgorithm;
use crate::provider::key_algorithm::eddsa::Eddsa;
use crate::provider::key_algorithm::key::KeyHandle;

pub async fn verify_did_log(
    log: &[(DidLogEntry, String)],
    did_method_provider: &dyn DidMethodProvider,
    params: &Params,
) -> Result<(), DidMethodError> {
    if let Some(limit) = params.max_did_log_entry_check {
        if log.len() > limit as usize {
            return Err(ResolutionError(format!(
                "Failed to verify did log: log has {} entries which is more than the max allowed length ({})",
                log.len(),
                limit
            )));
        }
    }

    let mut log_iter = log.iter().peekable();

    let Some((first_entry, first_line_raw)) = log_iter.peek() else {
        return Err(ResolutionError("Did log is empty".to_string()));
    };
    let Some(ref scid) = first_entry.parameters.scid else {
        return Err(ResolutionError("missing SCID".to_string()));
    };
    verify_scid(scid, first_line_raw)?;

    let mut active_parameters = first_entry.parameters.clone();
    let mut scid_or_version_id = &scid.clone();
    let mut last_entry_time = None;
    let now = OffsetDateTime::now_utc();

    for (index, (entry, raw_line)) in log_iter.enumerate() {
        // did log uses 1-based indices
        verify_version_id(scid_or_version_id, index + 1, raw_line)?;
        verify_proof(&active_parameters, entry, did_method_provider).await?;
        scid_or_version_id = &entry.version_id;

        if entry.version_time > now {
            return Err(ResolutionError(format!(
                "Invalid log entry {}: version time {} is in the future",
                entry.version_id, entry.version_time
            )));
        }

        if let Some(prev_time) = last_entry_time.replace(entry.version_time) {
            if prev_time > entry.version_time {
                return Err(ResolutionError(format!(
                    "Invalid log entry {}: version time {} is before version time of the previous entry",
                    entry.version_id, entry.version_time
                )));
            }
        }

        check_parameters(index, &entry.parameters)?;
        check_prerotation(index, &active_parameters, &entry.parameters)?;

        // apply parameter changes
        if let Some(update_keys) = entry.parameters.update_keys.as_ref() {
            active_parameters.update_keys = Some(update_keys.clone());
        }

        if !entry.parameters.next_key_hashes.is_empty() {
            active_parameters.next_key_hashes = entry.parameters.next_key_hashes.clone();
        }

        if !active_parameters.prerotation.is_some_and(|enabled| enabled) {
            active_parameters.prerotation = entry.parameters.prerotation;
        }
    }
    Ok(())
}

fn check_parameters(index: usize, parameters: &DidLogParameters) -> Result<(), DidMethodError> {
    if parameters.deactivated.unwrap_or_default() {
        return Err(Deactivated);
    }

    if index > 0 && parameters.portable.unwrap_or_default() {
        return Err(ResolutionError(
            "portable flag can only be set to true in first entry".to_string(),
        ));
    }

    let version_is_mandatory = index == 0;
    verify_version(parameters, version_is_mandatory)
}

fn check_prerotation(
    index: usize,
    active_parameters: &DidLogParameters,
    entry_parameters: &DidLogParameters,
) -> Result<(), DidMethodError> {
    if index > 0 {
        let prerotation = active_parameters.prerotation.unwrap_or_default();
        let entry_prerotation = entry_parameters.prerotation.unwrap_or_default();
        if prerotation && prerotation != entry_prerotation {
            return Err(ResolutionError(
                "prerotation set to true cannot be cannot be changed by subsequent entries"
                    .to_string(),
            ));
        }

        if prerotation {
            // update keys must be present when prerotation is enabled
            let Some(update_keys) = &entry_parameters.update_keys else {
                return Err(DidMethodError::ResolutionError(format!(
                    "Entry {} is missing update keys",
                    index + 1
                )));
            };

            for key in update_keys {
                let key_hash = SHA256.hash(key.as_bytes()).map_err(|err| {
                    DidMethodError::ResolutionError(format!("Failed to hash update key: {err}"))
                })?;

                let key_multihash = multihash_b58_encode(&key_hash)
                    .map_err(|err| DidMethodError::ResolutionError(format!("{err:#}")))?;

                if !active_parameters.next_key_hashes.contains(&key_multihash) {
                    return Err(DidMethodError::ResolutionError(format!(
                        "Update key {key} not found in nextKeyHashes"
                    )));
                }
            }
        }
    }

    Ok(())
}

fn verify_version(params: &DidLogParameters, mandatory: bool) -> Result<(), DidMethodError> {
    match params.method {
        Some(DidMethodVersion::V3) => Ok(()),
        None => {
            if mandatory {
                Err(ResolutionError("Missing method parameter".to_string()))
            } else {
                Ok(())
            }
        }
    }
}

fn verify_scid(scid: &str, first_line_raw: &str) -> Result<(), DidMethodError> {
    let replaced = first_line_raw.replace(scid, "{SCID}");
    let mut json_value = json_syntax::Value::from_str(&replaced).map_err(|err| {
        ResolutionError(format!("Failed to parse SCID hash input as JSON: {err}"))
    })?;
    let json_array = json_value
        .as_array_mut()
        .ok_or_else(|| ResolutionError("Log entry must be a JSON array".to_string()))?;
    if json_array.len() != 5 {
        return Err(ResolutionError(
            "Log entry must be a JSON array with 5 elements".to_string(),
        ));
    }

    json_array[0] = json!("{SCID}");
    json_array.pop(); // remove proof

    let hash = canonicalized_hash(json_value)?;
    let multihash = multihash::Multihash::<32>::wrap(0x12, &hash)
        .map_err(|err| ResolutionError(format!("Failed to create multihash: {err}")))?;

    let derived_scid = bs58::encode(multihash.to_bytes()).into_string();
    if scid != derived_scid {
        return Err(ResolutionError(format!(
            "Invalid SCID: expected {scid}, got {derived_scid}"
        )));
    };
    Ok(())
}

fn verify_version_id(
    scid_or_prev_version_id: &str,
    expected_index: usize,
    line_raw: &str,
) -> Result<(), DidMethodError> {
    let mut json_value = json_syntax::Value::from_str(line_raw).map_err(|err| {
        ResolutionError(format!("Failed to parse SCID hash input as JSON: {err}"))
    })?;
    let json_array = json_value
        .as_array_mut()
        .ok_or_else(|| ResolutionError("Log entry must be a JSON array".to_string()))?;
    if json_array.len() != 5 {
        return Err(ResolutionError(
            "Log entry must be a JSON array with 5 elements".to_string(),
        ));
    }
    let current_version_id = json_array[0]
        .as_str()
        .ok_or(ResolutionError(format!(
            "Expected versionId of type string but got '{}'.",
            json_array[0]
        )))?
        .to_string();
    let (index, expected_entry_hash) =
        current_version_id
            .split_once('-')
            .ok_or(ResolutionError(format!(
                "Invalid version_id '{current_version_id}'."
            )))?;

    if index != expected_index.to_string() {
        return Err(ResolutionError(format!(
            "Unexpected versionId '{current_version_id}', expected index {expected_index}, got {index}."
        )));
    }

    json_array[0] = json!(scid_or_prev_version_id);
    json_array.pop(); // remove proof

    let hash = canonicalized_hash(json_value)?;
    let multihash = multihash::Multihash::<32>::wrap(0x12, &hash)
        .map_err(|err| ResolutionError(format!("Failed to create multihash: {err}")))?;

    let entry_hash = bs58::encode(multihash.to_bytes()).into_string();
    if entry_hash != expected_entry_hash {
        return Err(ResolutionError(format!(
            "Entry hash mismatch, expected {expected_entry_hash}, got {entry_hash}."
        )));
    }
    Ok(())
}

async fn verify_proof(
    params: &DidLogParameters,
    entry: &DidLogEntry,
    did_method_provider: &dyn DidMethodProvider,
) -> Result<(), DidMethodError> {
    let mut proof = entry
        .proof
        .iter()
        .find(|proof| proof.cryptosuite == "eddsa-jcs-2022")
        .ok_or(ResolutionError(format!(
            "Found no integrity proof for log entry {} with cryptosuite 'eddsa-jcs-2022'.",
            entry.version_id
        )))?
        .clone();

    let Some(ref challenge) = proof.challenge else {
        return Err(ResolutionError(format!(
            "Missing proof challenge for log entry {}",
            entry.version_id
        )));
    };

    if let Some(proof_timestamp) = proof.created {
        if proof_timestamp < entry.version_time {
            return Err(ResolutionError(
                "Invalid proof: created time is before entry time.".to_string(),
            ));
        }
    }

    if *challenge != entry.version_id {
        return Err(ResolutionError(format!(
            "Proof challenge mismatch, expected {}, got {challenge}.",
            entry.version_id
        )));
    }

    let key_handle = verify_verification_method(params, did_method_provider, &proof).await?;

    // Take proof_value as it is not part of the message anyway
    let Some(signature_encoded) = proof.proof_value.take() else {
        return Err(ResolutionError(format!(
            "Missing proof_value for log entry {}",
            entry.version_id
        )));
    };
    let mut message = canonicalized_hash(
        json_syntax::to_value(proof)
            .map_err(|err| ResolutionError(format!("Failed to serialize proof: {err}")))?,
    )?;
    let mut doc_hash = canonicalized_hash(entry.state.value.source.clone())?;
    message.append(&mut doc_hash);

    let signature = bs58::decode(&signature_encoded[1..]) // drop the 'z' prefix
        .into_vec()
        .map_err(|err| ResolutionError(format!("Failed to decode proof_value: {err}")))?;
    key_handle.verify(&message, &signature).map_err(|err| {
        ResolutionError(format!(
            "Failed to verify integrity proof for log entry {}: {err}",
            entry.version_id
        ))
    })
}

async fn verify_verification_method(
    params: &DidLogParameters,
    did_method_provider: &dyn DidMethodProvider,
    proof: &VcdmProof,
) -> Result<KeyHandle, DidMethodError> {
    let did = DidValue::from_did_url(&proof.verification_method).map_err(|err| {
        ResolutionError(format!(
            "failed to parse verification method used for integrity proof: {err}"
        ))
    })?;
    let doc = did_method_provider.resolve(&did).await.map_err(|err| {
        ResolutionError(format!(
            "failed to resolve verification method used for integrity proof: {err}"
        ))
    })?;

    let Some(verification_method) = doc.find_verification_method(
        Some(&proof.verification_method),
        Some(KeyRole::Authentication),
    ) else {
        return Err(ResolutionError(format!(
            "Failed to find verification method {} in did document",
            proof.verification_method
        )));
    };

    let handle = Eddsa
        .parse_jwk(&verification_method.public_key_jwk)
        .map_err(|err| ResolutionError(format!("Failed to parse public key: {err}")))?;
    let multibase = handle.public_key_as_multibase().map_err(|err| {
        ResolutionError(format!("failed to encode public key as multibase {err}"))
    })?;

    if !params
        .update_keys
        .as_ref()
        .ok_or(ResolutionError(
            "Proof verification failed: missing update_keys".to_string(),
        ))?
        .contains(&multibase)
    {
        return Err(ResolutionError(format!(
            "Proof verification failed: verification method {} is not allowed update_key",
            proof.verification_method
        )));
    }
    Ok(handle)
}
