use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use serde_json::{Value, json};
use time::OffsetDateTime;

use super::{CRYPTOSUITE, KeyRef, LogEntry, SCID_PLACEHOLDER};
use crate::error::ContextWithErrorCode;
use crate::model::key::Key;
use crate::provider::credential_formatter::vcdm::VcdmProof;
use crate::provider::did_method::error::DidMethodError;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;

pub(super) fn resolution_error(message: impl Into<String>) -> DidMethodError {
    DidMethodError::ResolutionError(message.into())
}

// versionTime must be UTC ISO8601. We emit second precision, as in the spec's
// SCID example: https://identity.foundation/didwebvh/v1.0/#scid-generation-and-verification
pub(super) fn now_utc() -> Result<OffsetDateTime, DidMethodError> {
    crate::clock::now_utc()
        .replace_nanosecond(0)
        .map_err(|e| DidMethodError::CreationError(e.to_string()))
}

pub(super) fn make_keyref(
    key: &Key,
    key_provider: &dyn KeyProvider,
) -> Result<KeyRef, DidMethodError> {
    let storage = key_provider.get_key_storage(&key.storage_type)?;
    let handle = storage.key_handle(key).error_while("getting key handle")?;
    let multibase = handle
        .public_key_as_multibase()
        .error_while("getting key multibase")?;
    Ok(KeyRef { multibase, handle })
}

// SCIDs and entry hashes use JCS, SHA-256 multihash, and base58btc as specified in:
// https://identity.foundation/didwebvh/v1.0/#scid-generation-and-verification
// https://identity.foundation/didwebvh/v1.0/#entry-hash-generation-and-verification
fn canonicalized_hash(value: Value) -> Result<Vec<u8>, DidMethodError> {
    let mut value = json_syntax::Value::from_serde_json(value);
    value.canonicalize();
    SHA256
        .hash(value.to_string().as_bytes())
        .map_err(|e| resolution_error(format!("Failed to hash JSON: {e}")))
}

fn multihash_encode(hash: &[u8]) -> Result<String, DidMethodError> {
    let hash = multihash::Multihash::<32>::wrap(0x12, hash)?;
    Ok(bs58::encode(hash.to_bytes()).into_string())
}

// A pre-rotation commitment hashes the UTF-8 multikey string, not its decoded key bytes.
// https://identity.foundation/didwebvh/v1.0/#pre-rotation-key-hash-generation-and-verification
pub(super) fn hash_update_key(multikey: &str) -> Result<String, DidMethodError> {
    let hash = SHA256
        .hash(multikey.as_bytes())
        .map_err(|e| resolution_error(format!("Failed to hash update key: {e}")))?;
    multihash_encode(&hash)
}

pub(super) fn hash_json(value: &Value) -> Result<String, DidMethodError> {
    multihash_encode(&canonicalized_hash(value.clone())?)
}

pub(super) fn check_multihash(value: &str) -> Result<(), DidMethodError> {
    let decoded = bs58::decode(value)
        .into_vec()
        .map_err(|e| resolution_error(format!("Invalid multihash: {e}")))?;
    if decoded.len() != 34 || !decoded.starts_with(&[0x12, 0x20]) || value.len() != 46 {
        return Err(resolution_error("Expected SHA-256 base58btc multihash"));
    }
    Ok(())
}

pub(super) fn without_proof(mut value: Value) -> Result<Value, DidMethodError> {
    value
        .as_object_mut()
        .ok_or_else(|| resolution_error("Log entry must be an object"))?
        .remove("proof");
    Ok(value)
}

pub(super) fn hash_entry(value: &Value, predecessor: &str) -> Result<String, DidMethodError> {
    let mut value = without_proof(value.clone())?;
    value
        .as_object_mut()
        .ok_or_else(|| resolution_error("Log entry must be an object"))?
        .insert("versionId".to_string(), json!(predecessor));
    hash_json(&value)
}

pub(super) fn verify_scid(value: &Value, scid: &str) -> Result<(), DidMethodError> {
    let mut value = without_proof(value.clone())?;
    value
        .as_object_mut()
        .ok_or_else(|| resolution_error("Log entry must be an object"))?
        .insert("versionId".to_string(), json!(SCID_PLACEHOLDER));
    let replaced = serde_json::to_string(&value)?.replace(scid, SCID_PLACEHOLDER);
    let value: Value = serde_json::from_str(&replaced)?;
    if hash_json(&value)? != scid {
        return Err(resolution_error("SCID mismatch"));
    }
    Ok(())
}

// Each entry's assertionMethod proof covers the full entry without its proof property.
// https://identity.foundation/didwebvh/v1.0/#authorized-keys
fn proof_message(entry: &LogEntry, proof: &VcdmProof) -> Result<Vec<u8>, DidMethodError> {
    proof_message_raw(&serde_json::to_value(entry)?, &serde_json::to_value(proof)?)
}

pub(super) fn proof_message_raw(entry: &Value, proof: &Value) -> Result<Vec<u8>, DidMethodError> {
    let mut config = proof.clone();
    config
        .as_object_mut()
        .ok_or_else(|| resolution_error("Proof must be an object"))?
        .remove("proofValue");
    let mut message = canonicalized_hash(config)?;
    message.extend(canonicalized_hash(without_proof(entry.clone())?)?);
    Ok(message)
}

pub(super) fn normalize_document(
    mut state: Value,
    algorithms: &dyn KeyAlgorithmProvider,
) -> Result<Value, DidMethodError> {
    let document_id = state
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| resolution_error("Missing state.id"))?
        .to_string();
    // Internal DID documents require these fields. Some published JSON DID
    // documents omit them; fill them only after checking the original log's
    // SCID, entry hash, and proof against the published state.
    if state.get("@context").is_none() {
        state
            .as_object_mut()
            .ok_or_else(|| resolution_error("DID document must be an object"))?
            .insert(
                "@context".to_string(),
                json!(["https://www.w3.org/ns/did/v1"]),
            );
    }
    if let Some(methods) = state
        .get_mut("verificationMethod")
        .and_then(Value::as_array_mut)
    {
        for method in methods {
            let method = method
                .as_object_mut()
                .ok_or_else(|| resolution_error("Verification method must be an object"))?;
            if method.get("controller").is_none() {
                method.insert("controller".to_string(), json!(document_id));
            }
            let Some(multibase) = method.get("publicKeyMultibase").and_then(Value::as_str) else {
                continue;
            };
            if method.get("publicKeyJwk").is_some() {
                return Err(resolution_error(
                    "Verification method has two public key representations",
                ));
            }
            let public_key = algorithms
                .parse_multibase(multibase)
                .map_err(|e| {
                    resolution_error(format!("Unsupported verification method Multikey: {e}"))
                })?
                .key
                .public_key_as_jwk()
                .map_err(|e| {
                    resolution_error(format!("Invalid verification method Multikey: {e}"))
                })?;
            method.insert(
                "publicKeyJwk".to_string(),
                serde_json::to_value(public_key)?,
            );
        }
    }
    Ok(state)
}

pub(super) async fn build_proof(
    entry: &LogEntry,
    signer: &KeyRef,
    created: OffsetDateTime,
) -> Result<VcdmProof, DidMethodError> {
    let vm = format!("did:key:{}#{}", signer.multibase, signer.multibase);
    let mut proof = VcdmProof::builder()
        .cryptosuite(CRYPTOSUITE)
        .proof_purpose("assertionMethod")
        .verification_method(vm)
        .created(created)
        .build();
    let message = proof_message(entry, &proof)?;
    let signature = signer
        .handle
        .sign(&message)
        .await
        .error_while("signing DID log")?;
    proof.proof_value = Some(format!("z{}", bs58::encode(signature).into_string()));
    Ok(proof)
}
