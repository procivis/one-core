use error::KeyAlgorithmError;
use model::GeneratedKey;
use secrecy::SecretSlice;

use crate::config::core_config::KeyAlgorithmType;
use crate::model::key::{JwkUse, PrivateKeyJwk, PublicKeyJwk};
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_algorithm::model::KeyAlgorithmCapabilities;

pub mod bbs;
pub mod ecdsa;
pub mod eddsa;
pub mod error;
pub mod key;
pub mod ml_dsa;
pub mod model;
pub mod provider;

/// Find signer IDs and convert key representations.
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait KeyAlgorithm: Send + Sync {
    fn algorithm_id(&self) -> String;

    fn algorithm_type(&self) -> KeyAlgorithmType;

    fn get_capabilities(&self) -> KeyAlgorithmCapabilities;

    /// Generates a new in-memory key-pair.
    fn generate_key(&self) -> Result<GeneratedKey, KeyAlgorithmError>;

    fn reconstruct_key(
        &self,
        public_key: &[u8],
        private_key: Option<SecretSlice<u8>>,
        r#use: Option<JwkUse>,
    ) -> Result<KeyHandle, KeyAlgorithmError>;

    /// IANA jose/cose identifiers
    /// https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms
    /// https://www.iana.org/assignments/cose/cose.xhtml#algorithms
    /// https://datatracker.ietf.org/doc/html/draft-ietf-cose-dilithium
    fn issuance_jose_alg_id(&self) -> Option<String>;
    fn verification_jose_alg_ids(&self) -> Vec<String>;
    fn cose_alg_id(&self) -> Option<i32>;

    /// parse public keys coming from an external source
    fn parse_jwk(&self, key: &PublicKeyJwk) -> Result<KeyHandle, KeyAlgorithmError>;
    fn parse_private_jwk(&self, jwk: PrivateKeyJwk) -> Result<GeneratedKey, KeyAlgorithmError>;
    fn parse_multibase(&self, multibase: &str) -> Result<KeyHandle, KeyAlgorithmError>;
    fn parse_raw(&self, public_key_der: &[u8]) -> Result<KeyHandle, KeyAlgorithmError>;
}

pub(crate) fn parse_multibase_with_tag(
    encoded: &str,
    expected_tag: &[u8],
) -> Result<Vec<u8>, KeyAlgorithmError> {
    if !encoded.starts_with('z') {
        return Err(KeyAlgorithmError::Failed(format!(
            "Invalid multibase, expected 'z' prefix but got '{encoded}'"
        )));
    }
    let raw_bs58 = &encoded[1..];
    let decoded = bs58::decode(&raw_bs58)
        .into_vec()
        .map_err(|err| KeyAlgorithmError::Failed(format!("Invalid multibase suffix: {err}")))?;

    if decoded[..expected_tag.len()] != expected_tag[..] {
        return Err(KeyAlgorithmError::Failed(format!(
            "Invalid multibase tag, expected {}, but got {}",
            hex::encode(expected_tag),
            hex::encode(&decoded[..2])
        )));
    };
    Ok(decoded[expected_tag.len()..].to_vec())
}
