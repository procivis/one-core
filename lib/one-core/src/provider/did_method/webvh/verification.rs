use serde_json::Value;
use shared_types::DidValue;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::common::{
    check_multihash, hash_entry, hash_update_key, normalize_document, proof_message_raw,
    resolution_error, verify_scid,
};
use super::identifier::parse_did;
use super::{CRYPTOSUITE, DidWebvh, LogEntry, LogParameters, METHOD, VerifiedLog};
use crate::model::did::KeyRole;
use crate::provider::credential_formatter::vcdm::VcdmProof;
use crate::provider::did_method::dto::DidDocumentDTO;
use crate::provider::did_method::error::DidMethodError;
use crate::provider::key_algorithm::KeyAlgorithm;
use crate::provider::key_algorithm::eddsa::Eddsa;
use crate::provider::key_algorithm::key::KeyHandle;

#[derive(Default)]
struct VerificationState {
    previous_version_id: Option<String>,
    previous_time: Option<OffsetDateTime>,
    active_keys: Vec<String>,
    next_key_hashes: Vec<String>,
    deactivated: bool,
    first_did: Option<DidValue>,
    scid: Option<String>,
}

impl VerificationState {
    fn apply(&mut self, entry: &LogEntry, time: OffsetDateTime, did: DidValue) {
        if self.first_did.is_none() {
            self.first_did = Some(did);
        }
        if let Some(keys) = &entry.parameters.update_keys {
            self.active_keys = keys.clone();
        }
        if let Some(hashes) = &entry.parameters.next_key_hashes {
            self.next_key_hashes = hashes.clone();
        }
        self.previous_time = Some(time);
        self.previous_version_id = Some(entry.version_id.clone());
        self.deactivated = entry.parameters.deactivated.unwrap_or(false);
    }
}

impl DidWebvh {
    /// Process and verify every log entry in order.
    /// https://identity.foundation/didwebvh/v1.0/#read-resolve
    pub(super) async fn verify_log(
        &self,
        log: &str,
        expected_did: Option<&DidValue>,
    ) -> Result<VerifiedLog, DidMethodError> {
        let lines: Vec<_> = log.lines().collect();
        if lines.is_empty() {
            return Err(resolution_error("DID log is empty"));
        }
        if let Some(limit) = self.params.max_did_log_entry_check
            && lines.len() > limit as usize
        {
            return Err(resolution_error("DID log has too many entries"));
        }

        let mut state = VerificationState::default();
        let mut entries = Vec::with_capacity(lines.len());
        for (index, line) in lines.into_iter().enumerate() {
            entries.push(
                self.verify_log_entry(line, index, expected_did, &mut state)
                    .await?,
            );
        }
        Ok(VerifiedLog {
            entries,
            active_keys: state.active_keys,
            deactivated: state.deactivated,
        })
    }

    /// Check the properties of one entry against the verified preceding state.
    /// https://identity.foundation/didwebvh/v1.0/#read-resolve
    async fn verify_log_entry(
        &self,
        line: &str,
        index: usize,
        expected_did: Option<&DidValue>,
        state: &mut VerificationState,
    ) -> Result<LogEntry, DidMethodError> {
        if state.deactivated {
            return Err(resolution_error("Entry after deactivation"));
        }
        let (raw, entry) = parse_log_entry(line)?;
        let params = &entry.parameters;
        verify_method(params, index)?;
        verify_portable(params, index)?;
        verify_witness(params, index)?;
        verify_watchers(params, index)?;
        verify_scid_parameter(params, &raw, index, state)?;
        verify_ttl(params)?;
        verify_update_keys(params, index)?;
        let proof_keys = authorized_keys_for_entry(params, index, state)?;
        let time = self.verify_version_time(&entry.version_time, state.previous_time)?;
        let did = verify_state_id(&entry.state, expected_did, state)?;
        verify_version_id(&entry.version_id, &raw, index, state)?;
        self.verify_proofs(&entry, &raw, &proof_keys).await?;
        self.verify_document(&entry.state)?;
        state.apply(&entry, time, did);
        Ok(entry)
    }

    /// Check UTC format, monotonicity, and future-time tolerance.
    /// https://identity.foundation/didwebvh/v1.0/#read-resolve
    fn verify_version_time(
        &self,
        value: &str,
        previous: Option<OffsetDateTime>,
    ) -> Result<OffsetDateTime, DidMethodError> {
        let time = OffsetDateTime::parse(value, &Rfc3339)
            .map_err(|e| resolution_error(format!("Invalid versionTime: {e}")))?;
        if time.offset() != time::UtcOffset::UTC
            || !(value.ends_with('Z') || value.ends_with("+00:00"))
            || previous.is_some_and(|previous| time <= previous)
            || time > crate::clock::now_utc() + self.params.leeway_seconds
        {
            return Err(resolution_error("Invalid versionTime sequence"));
        }
        Ok(time)
    }

    /// Map a verified DID document to the internal representation.
    /// https://identity.foundation/didwebvh/v1.0/#the-did-log-file
    fn verify_document(&self, state: &Value) -> Result<(), DidMethodError> {
        let document = normalize_document(state.clone(), self.key_algorithm_provider.as_ref())?;
        let _document: DidDocumentDTO = serde_json::from_value(document)
            .map_err(|e| resolution_error(format!("Invalid DID document: {e}")))?;
        Ok(())
    }

    /// Require a Data Integrity assertionMethod proof from an authorized key.
    /// https://identity.foundation/didwebvh/v1.0/#authorized-keys
    async fn verify_proofs(
        &self,
        entry: &LogEntry,
        raw: &Value,
        authorized_keys: &[String],
    ) -> Result<(), DidMethodError> {
        if entry.proof.is_empty() {
            return Err(resolution_error("Missing log entry proof"));
        }
        for (index, proof) in entry.proof.iter().enumerate() {
            let raw_proof = raw
                .get("proof")
                .and_then(|proofs| proofs.get(index))
                .ok_or_else(|| resolution_error("Missing log entry proof"))?;
            self.verify_proof(proof, raw_proof, raw, authorized_keys)
                .await?;
        }
        Ok(())
    }

    /// Verify one log-entry proof, including its options, signer, and signature.
    /// https://identity.foundation/didwebvh/v1.0/#authorized-keys
    async fn verify_proof(
        &self,
        proof: &VcdmProof,
        raw_proof: &Value,
        raw_entry: &Value,
        authorized_keys: &[String],
    ) -> Result<(), DidMethodError> {
        verify_proof_options(proof)?;
        let handle = self.resolve_authorized_key(proof, authorized_keys).await?;
        verify_proof_signature(&handle, proof, raw_proof, raw_entry)
    }

    /// Require a did:key verification method matching an active update key.
    /// https://identity.foundation/didwebvh/v1.0/#authorized-keys
    async fn resolve_authorized_key(
        &self,
        proof: &VcdmProof,
        authorized_keys: &[String],
    ) -> Result<KeyHandle, DidMethodError> {
        let did = parse_proof_did(proof)?;
        let handle = self.resolve_proof_key_handle(&did, proof).await?;
        let multibase = handle
            .public_key_as_multibase()
            .map_err(|e| resolution_error(format!("Invalid update key: {e}")))?;
        verify_proof_key_reference(&did, proof, &multibase, authorized_keys)?;
        Ok(handle)
    }

    /// Resolve the did:key assertionMethod named by a proof.
    /// https://identity.foundation/didwebvh/v1.0/#authorized-keys
    async fn resolve_proof_key_handle(
        &self,
        did: &DidValue,
        proof: &VcdmProof,
    ) -> Result<KeyHandle, DidMethodError> {
        let document = self
            .did_method_provider
            .resolve(did)
            .await
            .map_err(|e| resolution_error(format!("Failed to resolve update key: {e}")))?;
        let vm = document
            .find_verification_method(
                Some(&proof.verification_method),
                Some(KeyRole::AssertionMethod),
            )
            .ok_or_else(|| resolution_error("Update verificationMethod not found"))?;
        Eddsa
            .parse_jwk(&vm.public_key_jwk)
            .map_err(|e| resolution_error(format!("Invalid update key: {e}")))
    }
}

/// Require a did:key identifier in a log-entry proof.
/// https://identity.foundation/didwebvh/v1.0/#authorized-keys
fn parse_proof_did(proof: &VcdmProof) -> Result<DidValue, DidMethodError> {
    let did = DidValue::from_did_url(&proof.verification_method)
        .map_err(|e| resolution_error(format!("Invalid verificationMethod: {e}")))?;
    if did.method() != "key" {
        return Err(resolution_error(
            "Update verificationMethod must be did:key",
        ));
    }
    Ok(did)
}

/// Bind the proof fragment to its did:key body and the active updateKeys.
/// https://identity.foundation/didwebvh/v1.0/#authorized-keys
fn verify_proof_key_reference(
    did: &DidValue,
    proof: &VcdmProof,
    multibase: &str,
    authorized_keys: &[String],
) -> Result<(), DidMethodError> {
    if did.as_str() != format!("did:key:{multibase}")
        || proof.verification_method != format!("did:key:{multibase}#{multibase}")
    {
        return Err(resolution_error("Invalid did:key verification method"));
    }
    if !authorized_keys.iter().any(|key| key == multibase) {
        return Err(resolution_error("Proof key is not an active update key"));
    }
    Ok(())
}

/// Parse one JSON Lines record without changing its signed representation.
/// https://identity.foundation/didwebvh/v1.0/#the-did-log-file
fn parse_log_entry(line: &str) -> Result<(Value, LogEntry), DidMethodError> {
    let raw: Value = serde_json::from_str(line)
        .map_err(|e| resolution_error(format!("Invalid log entry: {e}")))?;
    let entry: LogEntry = serde_json::from_value(raw.clone())
        .map_err(|e| resolution_error(format!("Invalid log entry: {e}")))?;
    Ok((raw, entry))
}

/// The first entry selects a supported method version; later entries inherit it.
/// https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters
fn verify_method(params: &LogParameters, index: usize) -> Result<(), DidMethodError> {
    if index == 0 && params.method.as_deref() != Some(METHOD) {
        return Err(first_entry_profile_error());
    }
    if params
        .method
        .as_deref()
        .is_some_and(|method| method != METHOD)
    {
        return Err(resolution_error("Unsupported did:webvh parameter"));
    }
    Ok(())
}

/// The Swiss method profile excludes DID portability.
/// https://swiyu-admin-ch.github.io/specifications/swiss-profile-anchor/#3-didwebvh-did-method-specification
fn verify_portable(params: &LogParameters, index: usize) -> Result<(), DidMethodError> {
    if index == 0 && params.portable != Some(false) {
        return Err(first_entry_profile_error());
    }
    if params.portable == Some(true) {
        return Err(resolution_error("Unsupported did:webvh parameter"));
    }
    Ok(())
}

/// The Swiss method profile excludes witnesses; omission has the empty-object default.
/// https://swiyu-admin-ch.github.io/specifications/swiss-profile-anchor/#3-didwebvh-did-method-specification
/// https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters
fn verify_witness(params: &LogParameters, index: usize) -> Result<(), DidMethodError> {
    if params
        .witness
        .as_ref()
        .is_some_and(|witness| !witness.is_empty())
    {
        return Err(if index == 0 {
            first_entry_profile_error()
        } else {
            resolution_error("Unsupported did:webvh parameter")
        });
    }
    Ok(())
}

/// The Swiss method profile excludes watchers; omission has the empty-array default.
/// https://swiyu-admin-ch.github.io/specifications/swiss-profile-anchor/#3-didwebvh-did-method-specification
/// https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters
fn verify_watchers(params: &LogParameters, index: usize) -> Result<(), DidMethodError> {
    if params
        .watchers
        .as_ref()
        .is_some_and(|watchers| !watchers.is_empty())
    {
        return Err(if index == 0 {
            first_entry_profile_error()
        } else {
            resolution_error("Unsupported did:webvh parameter")
        });
    }
    Ok(())
}

fn first_entry_profile_error() -> DidMethodError {
    resolution_error("Invalid first-entry method or Swiss profile parameters")
}

/// Verify the initial SCID once and reject later SCID parameters.
/// https://identity.foundation/didwebvh/v1.0/#scid-generation-and-verification
fn verify_scid_parameter(
    params: &LogParameters,
    raw: &Value,
    index: usize,
    state: &mut VerificationState,
) -> Result<(), DidMethodError> {
    if index == 0 {
        let scid = params
            .scid
            .as_ref()
            .ok_or_else(|| resolution_error("Missing SCID"))?;
        check_multihash(scid)?;
        verify_scid(raw, scid)?;
        state.scid = Some(scid.clone());
    } else if params.scid.is_some() {
        return Err(resolution_error("SCID may only appear in the first entry"));
    }
    Ok(())
}

/// Check the supported TTL range.
/// https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters
fn verify_ttl(params: &LogParameters) -> Result<(), DidMethodError> {
    if params.ttl.is_some_and(|ttl| ttl > i32::MAX as u64) {
        return Err(resolution_error("Invalid ttl"));
    }
    Ok(())
}

/// Check the public-key format and the required initial updateKeys list.
/// https://identity.foundation/didwebvh/v1.0/#authorized-keys
fn verify_update_keys(params: &LogParameters, index: usize) -> Result<(), DidMethodError> {
    if index == 0 {
        let keys = params
            .update_keys
            .as_ref()
            .ok_or_else(|| resolution_error("Missing updateKeys"))?;
        if keys.is_empty() {
            return Err(resolution_error("Empty first-entry updateKeys"));
        }
    }
    if let Some(keys) = &params.update_keys {
        for key in keys {
            Eddsa
                .parse_multibase(key)
                .map_err(|e| resolution_error(format!("Invalid update key: {e}")))?;
        }
    }
    Ok(())
}

/// Apply the pre-rotation commitment to every current update key, then select proof keys.
/// https://identity.foundation/didwebvh/v1.0/#pre-rotation-key-hash-generation-and-verification
fn authorized_keys_for_entry(
    params: &LogParameters,
    index: usize,
    state: &VerificationState,
) -> Result<Vec<String>, DidMethodError> {
    if index == 0 {
        return params
            .update_keys
            .clone()
            .ok_or_else(|| resolution_error("Missing updateKeys"));
    }
    if state.next_key_hashes.is_empty() {
        return Ok(state.active_keys.clone());
    }
    let keys = params
        .update_keys
        .as_ref()
        .ok_or_else(|| resolution_error("Pre-rotation requires explicit updateKeys"))?;
    if params.next_key_hashes.is_none() {
        return Err(resolution_error(
            "Pre-rotation requires explicit nextKeyHashes",
        ));
    }
    if keys.is_empty() {
        return Err(resolution_error("Pre-rotation requires update keys"));
    }
    for key in keys {
        if !state.next_key_hashes.contains(&hash_update_key(key)?) {
            return Err(resolution_error("Update key has no prior commitment"));
        }
    }
    Ok(keys.clone())
}

/// Check state.id against the initial SCID, the initial DID, and the requested DID.
/// https://identity.foundation/didwebvh/v1.0/#read-resolve
fn verify_state_id(
    document: &Value,
    expected_did: Option<&DidValue>,
    state: &VerificationState,
) -> Result<DidValue, DidMethodError> {
    let did: DidValue = document
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| resolution_error("Missing state.id"))?
        .parse()
        .map_err(|e| resolution_error(format!("Invalid state.id: {e}")))?;
    let state_scid = parse_did(&did)?.0;
    if Some(state_scid) != state.scid.as_deref() {
        return Err(resolution_error("state.id SCID mismatch"));
    }
    if state.first_did.as_ref().is_some_and(|first| first != &did) {
        return Err(resolution_error("DID portability is not supported"));
    }
    if expected_did.is_some_and(|expected| expected != &did) {
        return Err(resolution_error("DID log does not match requested DID"));
    }
    Ok(did)
}

/// Verify the sequential version number and hash chain for every entry.
/// https://identity.foundation/didwebvh/v1.0/#entry-hash-generation-and-verification
fn verify_version_id(
    version_id: &str,
    raw: &Value,
    index: usize,
    state: &VerificationState,
) -> Result<(), DidMethodError> {
    let (number, entry_hash) = version_id
        .split_once('-')
        .ok_or_else(|| resolution_error("Invalid versionId"))?;
    if number != (index + 1).to_string() || entry_hash.contains('-') {
        return Err(resolution_error("Invalid version number"));
    }
    check_multihash(entry_hash)?;
    let predecessor = state
        .previous_version_id
        .as_deref()
        .or(state.scid.as_deref())
        .ok_or_else(|| resolution_error("Missing predecessor"))?;
    if entry_hash != hash_entry(raw, predecessor)? {
        return Err(resolution_error("Entry hash mismatch"));
    }
    Ok(())
}

/// Check the proof type, cryptosuite, and purpose permitted by method 1.0.
/// https://identity.foundation/didwebvh/v1.0/#authorized-keys
fn verify_proof_options(proof: &VcdmProof) -> Result<(), DidMethodError> {
    if proof.r#type != "DataIntegrityProof"
        || proof.cryptosuite != CRYPTOSUITE
        || proof.proof_purpose != "assertionMethod"
    {
        return Err(resolution_error("Invalid log entry proof options"));
    }
    Ok(())
}

/// Verify the EdDSA Data Integrity signature over the entry without proof.
/// https://identity.foundation/didwebvh/v1.0/#authorized-keys
fn verify_proof_signature(
    handle: &KeyHandle,
    proof: &VcdmProof,
    raw_proof: &Value,
    raw_entry: &Value,
) -> Result<(), DidMethodError> {
    let signature = proof
        .proof_value
        .as_deref()
        .and_then(|value| value.strip_prefix('z'))
        .ok_or_else(|| resolution_error("Missing or invalid proofValue"))?;
    let signature = bs58::decode(signature)
        .into_vec()
        .map_err(|e| resolution_error(format!("Invalid proofValue: {e}")))?;
    let message = proof_message_raw(raw_entry, raw_proof)?;
    handle
        .verify(&message, &signature)
        .map_err(|e| resolution_error(format!("Invalid log entry proof: {e}")))
}
