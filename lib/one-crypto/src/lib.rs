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
    signers: HashMap<String, Arc<dyn Signer>>,
}

impl CryptoProviderImpl {
    pub fn new(
        hashers: HashMap<String, Arc<dyn Hasher>>,
        signers: HashMap<String, Arc<dyn Signer>>,
    ) -> Self {
        Self { hashers, signers }
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

    fn get_signer(&self, signer: &str) -> Result<Arc<dyn Signer>, CryptoProviderError> {
        Ok(self
            .signers
            .get(signer)
            .ok_or(CryptoProviderError::MissingHasher(signer.to_owned()))?
            .clone())
    }
}

#[derive(Debug, PartialEq, Eq, Error, Clone)]
pub enum CryptoProviderError {
    #[error("Missing hasher: `{0}`")]
    MissingHasher(String),
    #[error("Missing signer: `{0}`")]
    MissingSigner(String),
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
    #[error("Missing algorithm `{0}`")]
    MissingAlgorithm(String),
    #[error("Missing key")]
    MissingKey,
    #[error("Missing key reference")]
    MissingKeyReference,
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

    /// Returns signer instance.
    fn get_signer(&self, signer: &str) -> Result<Arc<dyn Signer>, CryptoProviderError>;
}
