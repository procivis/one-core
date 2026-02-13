use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use time::OffsetDateTime;

use crate::error::ContextWithErrorCode;
use crate::model::key::Key;
use crate::provider::credential_formatter::vcdm::VcdmProof;
use crate::provider::did_method::error::DidMethodError;
use crate::provider::did_method::webvh::deserialize::DidMethodVersion;
use crate::provider::did_method::webvh::serialize::DidLogEntry;
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_storage::provider::KeyProvider;
use crate::service::error::MissingProviderError;

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

pub fn multihash_b58_encode(input: &[u8]) -> Result<String, multihash::Error> {
    let multihash = multihash::Multihash::<32>::wrap(0x12, input)?;
    Ok(bs58::encode(multihash.to_bytes()).into_string())
}

pub(super) fn canonicalize_multihash_encode(log: impl Serialize) -> Result<String, DidMethodError> {
    let json = json_syntax::to_value(log)?;
    let hash = canonicalized_hash(json)?;
    Ok(multihash_b58_encode(&hash)?)
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
    let storage = key_provider
        .get_key_storage(&key.storage_type)
        .ok_or(MissingProviderError::KeyStorage(
            key.storage_type.to_string(),
        ))
        .error_while("getting key storage")?;

    let key_handle = storage.key_handle(key).error_while("getting key handle")?;

    let multibase = key_handle
        .public_key_as_multibase()
        .error_while("getting key multibase")?;

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

    let json = json_syntax::to_value(&proof)?;
    let mut proof_hash = canonicalized_hash(json)?;

    let json = json_syntax::to_value(&log.state.value)?;
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
        .error_while("signing")?;

    proof.proof_value = Some(proof_value);

    Ok(proof)
}
