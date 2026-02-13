//! Signing and verifying of raw bytes.
//!
//! This module provides utilities for hashing and direct signatures and verifications
//! of raw bytes. It has been separated into its own directory to enable future
//! certification, e.g. in the [NIST Cryptographic Module Validation Program (CMVP)][cmvp].
//!
//! [cmvp]: https://csrc.nist.gov/Projects/Cryptographic-Module-Validation-Program
//! Implementation of the Crypto provider, for hashing and signing.

use std::collections::HashMap;
use std::sync::Arc;

use hmac::Hmac;
use secrecy::SecretSlice;
use sha2::Sha256;
use thiserror::Error;

use crate::hasher::sha256::SHA256;

pub mod encryption;
pub mod hasher;
pub mod jwe;
pub mod signer;
pub mod utilities;

mod password;

type HmacSha256 = Hmac<Sha256>;

#[cfg(test)]
mod test;

#[derive(Clone)]
pub struct CryptoProviderImpl {
    hashers: HashMap<String, Arc<dyn Hasher>>,
}

impl CryptoProviderImpl {
    pub fn new(hashers: HashMap<String, Arc<dyn Hasher>>) -> Self {
        Self { hashers }
    }
}

impl CryptoProvider for CryptoProviderImpl {
    fn get_hasher(&self, hasher: &str) -> Result<Arc<dyn Hasher>, CryptoProviderError> {
        Ok(self
            .hashers
            .get(hasher)
            .ok_or(CryptoProviderError::MissingHasher(hasher.to_owned()))?
            .clone())
    }
}

#[derive(Debug, PartialEq, Eq, Error, Clone)]
pub enum CryptoProviderError {
    #[error("Missing hasher: `{0}`")]
    MissingHasher(String),
}

#[derive(Debug, PartialEq, Eq, Error)]
pub enum HasherError {
    #[error("Could not hash")]
    CouldNotHash,
    #[error("Crypto provider error: `{0}`")]
    CryptoError(#[from] CryptoProviderError),
}

#[derive(Debug, PartialEq, Eq, Error, Clone)]
pub enum SignerError {
    #[error("Could not generate key pair: `{0}`")]
    CouldNotGenerateKeyPair(String),
    #[error("Crypto provider error: `{0}`")]
    CryptoError(#[from] CryptoProviderError),
    #[error("Could not sign: `{0}`")]
    CouldNotSign(String),
    #[error("Could not extract keypair")]
    CouldNotExtractKeyPair,
    #[error("Could not extract public key: `{0}`")]
    CouldNotExtractPublicKey(String),
    #[error("Could not extract private key: `{0}`")]
    CouldNotExtractPrivateKey(String),
    #[error("Could not verify: `{0}`")]
    CouldNotVerify(String),
    #[error("Invalid signature")]
    InvalidSignature,
}

/// Provides hashing.
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait Hasher: Send + Sync {
    /// Hasher.
    fn hash_base64(&self, input: &[u8]) -> Result<String, HasherError>;

    fn hash_base64_url(&self, input: &[u8]) -> Result<String, HasherError>;

    /// Hasher.
    fn hash(&self, input: &[u8]) -> Result<Vec<u8>, HasherError>;
}

/// Generally the [key storage][ks] module or [credential formatter][cf] module is used for safe signing,
/// but direct signing and verification is possible here.
///
/// [ks]: ../../one_providers/key_storage/index.html
/// [cf]: ../../one_providers/credential_formatter/index.html
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait Signer: Send + Sync {
    /// Direct signing.
    fn sign(
        &self,
        input: &[u8],
        public_key: &[u8],
        private_key: &SecretSlice<u8>,
    ) -> Result<Vec<u8>, SignerError>;

    /// Direct signature verification.
    fn verify(&self, input: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), SignerError>;
}

/// Return hasher or signer instances. Not supported for all key storage types.
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait CryptoProvider: Send + Sync {
    /// Returns hasher instance.
    fn get_hasher(&self, hasher: &str) -> Result<Arc<dyn Hasher>, CryptoProviderError>;
}

pub fn initialize_crypto_provider() -> Arc<dyn CryptoProvider> {
    let hashers: Vec<(String, Arc<dyn Hasher>)> = vec![("sha-256".to_string(), Arc::new(SHA256))];

    Arc::new(CryptoProviderImpl::new(HashMap::from_iter(hashers)))
}
