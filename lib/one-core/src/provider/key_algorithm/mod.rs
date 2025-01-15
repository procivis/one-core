use error::KeyAlgorithmError;
use model::GeneratedKey;
use zeroize::Zeroizing;

use crate::model::key::PublicKeyJwk;

pub mod bbs;
pub mod eddsa;
pub mod error;
pub mod es256;
pub mod ml_dsa;
pub mod model;
pub mod provider;

/// Find signer IDs and convert key representations.
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait KeyAlgorithm: Send + Sync {
    /// Finds related crypto signer ID.
    fn get_signer_algorithm_id(&self) -> String;

    /// Returns base58-btc representation of a public key.
    fn get_multibase(&self, public_key: &[u8]) -> Result<String, KeyAlgorithmError>;

    /// Generates a new in-memory key-pair.
    fn generate_key_pair(&self) -> GeneratedKey;

    /// Converts public key bytes to JWK.
    fn bytes_to_jwk(
        &self,
        bytes: &[u8],
        r#use: Option<String>,
    ) -> Result<PublicKeyJwk, KeyAlgorithmError>;

    /// Converts JWK to key bytes.
    fn jwk_to_bytes(&self, jwk: &PublicKeyJwk) -> Result<Vec<u8>, KeyAlgorithmError>;

    /// Converts a private key to JWK. **Use carefully.**
    ///
    /// This can be useful for certain APIs that require JWK. Not supported by all
    /// storage methods.
    ///
    /// Zeroize is used to ensure memory erasure.
    fn private_key_as_jwk(
        &self,
        _secret_key: Zeroizing<Vec<u8>>,
    ) -> Result<Zeroizing<String>, KeyAlgorithmError> {
        Err(KeyAlgorithmError::NotSupported(
            std::any::type_name::<Self>().to_string(),
        ))
    }

    /// Converts a public key from DER to bytes.
    fn public_key_from_der(&self, public_key_der: &[u8]) -> Result<Vec<u8>, KeyAlgorithmError>;
    fn get_capabilities(&self) -> model::KeyAlgorithmCapabilities;

    /// get JOSE algorithm identifier
    /// https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms
    ///
    /// First entry (if any) is the correct identifier according to IANA
    ///
    /// Optional additional entries are for backward compatibility,
    /// intended to be used when parsing an incoming JOSE header
    fn jose_alg(&self) -> Vec<String>;
}
