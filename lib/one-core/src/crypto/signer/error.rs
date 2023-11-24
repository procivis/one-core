use thiserror::Error;

use crate::crypto::error::CryptoProviderError;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum SignerError {
    #[error("Crypto provider error: `{0}`")]
    CryptoError(#[from] CryptoProviderError),
    #[error("Could not sign: `{0}`")]
    CouldNotSign(String),
    #[error("Could not extract keypair")]
    CouldNotExtractKeyPair,
    #[error("Could not extract public key: `{0}`")]
    CouldNotExtractPublicKey(String),
    #[error("Could not verify: `{0}`")]
    CouldNotVerify(String),
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Missing algorithm `{0}`")]
    MissingAlgorithm(String),
    #[error("Missing key")]
    MissingKey,
}
