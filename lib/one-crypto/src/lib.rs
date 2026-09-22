//! Signing and verifying of raw bytes.
//!
//! This module provides utilities for hashing and direct signatures and verifications
//! of raw bytes. It has been separated into its own directory to enable future
//! certification, e.g. in the [NIST Cryptographic Module Validation Program (CMVP)][cmvp].
//!
//! [cmvp]: https://csrc.nist.gov/Projects/Cryptographic-Module-Validation-Program

use std::sync::Arc;

use hmac::Hmac;
use secrecy::SecretSlice;
use sha2::{Sha256, Sha512};
use standardized_types::iana;
use thiserror::Error;

use crate::hasher::sha256::SHA256;
use crate::hasher::sha512::SHA512;

pub mod encryption;
pub mod hasher;
pub mod jwe;
pub mod rand08;
pub mod signer;
pub mod utilities;

mod password;

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

#[cfg(test)]
mod test;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum HasherError {
    #[error("Could not hash")]
    CouldNotHash,
    #[error("Missing hasher: `{0}`")]
    MissingHasher(String),
}

#[derive(Debug, PartialEq, Eq, Error, Clone)]
pub enum SignerError {
    #[error("Could not generate key pair: `{0}`")]
    CouldNotGenerateKeyPair(String),
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
    #[error("HMAC error: `{0}`")]
    HmacError(String),
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

pub fn get_hasher(algorithm: iana::HashAlgorithm) -> Result<Arc<dyn Hasher>, HasherError> {
    Ok(match algorithm {
        iana::HashAlgorithm::Sha256 => Arc::new(SHA256),
        iana::HashAlgorithm::Sha512 => Arc::new(SHA512),
        other => {
            return Err(HasherError::MissingHasher(other.to_string()));
        }
    })
}
