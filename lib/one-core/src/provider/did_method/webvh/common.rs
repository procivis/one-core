use anyhow::Context;
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use time::OffsetDateTime;

use crate::model::key::Key;
use crate::provider::credential_formatter::vcdm::VcdmProof;
use crate::provider::did_method::error::DidMethodError;
use crate::provider::did_method::webvh::deserialize::DidMethodVersion;
use crate::provider::did_method::webvh::serialize::DidLogEntry;
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_storage::provider::KeyProvider;

pub(super) const CRYPTOSUITE: &str = "eddsa-jcs-2022";

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(super) struct DidLogParameters {
    pub method: Option<DidMethodVersion>,
    pub prerotation: Option<bool>,
    pub portable: Option<bool>,
    #[serde(default)]
    pub update_keys: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub next_key_hashes: Vec<String>,
    pub scid: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub witness: Vec<String>,
    pub deactivated: Option<bool>,
    pub ttl: Option<u32>,
}

pub(super) struct KeyRef {
    pub multibase: String,
    pub handle: KeyHandle,
}

pub fn canonicalized_hash(mut data: json_syntax::Value) -> Result<Vec<u8>, DidMethodError> {
    data.canonicalize();
    SHA256.hash(data.to_string().as_bytes()).map_err(|err| {
        DidMethodError::ResolutionError(format!("Failed to hash canonicalized JSON: {err}"))
    })
}

pub fn multihash_b58_encode(input: &[u8]) -> Result<String, anyhow::Error> {
    let multihash =
        multihash::Multihash::<32>::wrap(0x12, input).context("Failed to create multihash")?;

    Ok(bs58::encode(multihash.to_bytes()).into_string())
}

pub(super) fn canonicalize_multihash_encode(log: impl Serialize) -> Result<String, DidMethodError> {
    let json = json_syntax::to_value(log)
        .map_err(|err| DidMethodError::CouldNotCreate(format!("failed serializing log: {err}")))?;
    let hash = canonicalized_hash(json)?;

    multihash_b58_encode(&hash).map_err(|err| DidMethodError::CouldNotCreate(format!("{err:#}")))
}

pub(super) fn now_utc() -> OffsetDateTime {
    #[allow(clippy::expect_used)]
    OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .expect("should always be safe to replace with 0")
}

pub(crate) fn update_version(entry: &mut DidLogEntry, index: usize, entry_hash: &str) {
    entry.version_id = format!("{index}-{entry_hash}");
}

pub(crate) fn make_keyref(
    key: &Key,
    key_provider: &dyn KeyProvider,
) -> Result<KeyRef, DidMethodError> {
    let Some(storage) = key_provider.get_key_storage(&key.storage_type) else {
        return Err(DidMethodError::CouldNotCreate(format!(
            "missing key storage for storage type: {}",
            key.storage_type
        )));
    };

    let key_handle = storage.key_handle(key).map_err(|err| {
        DidMethodError::CouldNotCreate(format!("failed getting key handle for key: {err}"))
    })?;

    let multibase = key_handle.public_key_as_multibase().map_err(|err| {
        DidMethodError::CouldNotCreate(format!("failed converting key to multibase: {err}"))
    })?;

    Ok(KeyRef {
        multibase,
        handle: key_handle,
    })
}

pub(crate) async fn build_proof(
    log: &DidLogEntry,
    active_key: &KeyRef,
    created: OffsetDateTime,
) -> Result<VcdmProof, DidMethodError> {
    let verification_method = format!("did:key:{}#{}", active_key.multibase, active_key.multibase);
    let mut proof = VcdmProof::builder()
        .proof_purpose("authentication")
        .cryptosuite(CRYPTOSUITE)
        .created(created)
        .challenge(log.version_id.clone())
        .verification_method(verification_method)
        .build();

    let json = json_syntax::to_value(&proof).map_err(|err| {
        DidMethodError::CouldNotCreate(format!("failed serializing proof: {err}"))
    })?;
    let mut proof_hash = canonicalized_hash(json)?;

    let json = json_syntax::to_value(&log.state.value).map_err(|err| {
        DidMethodError::CouldNotCreate(format!("failed serializing did doc: {err}"))
    })?;
    let did_doc_hash = canonicalized_hash(json)?;
    proof_hash.extend(did_doc_hash);

    let proof_value = active_key
        .handle
        .sign(&proof_hash)
        .await
        .map(|s| {
            let encoded = bs58::encode(s).into_string();
            format!("z{encoded}")
        })
        .map_err(|err| DidMethodError::CouldNotCreate(format!("failed signing did log: {err}")))?;

    proof.proof_value = Some(proof_value);

    Ok(proof)
}
