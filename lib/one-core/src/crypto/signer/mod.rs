use thiserror::Error;

pub mod eddsa;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum SignerError {
    #[error("Could not sign")]
    CouldNotSign,
    #[error("Could not extract keypair")]
    CouldNotExtractKeyPair,
    #[error("Could not extract public key")]
    CouldNotExtractPublicKey,
    #[error("Could not verify")]
    CouldNotVerify,
    #[error("Invalid signature")]
    InvalidSignature,
}

pub trait Signer {
    fn sign(&self, input: &str, key: &[u8]) -> Result<Vec<u8>, SignerError>;
    fn verify(&self, input: &str, signature: &[u8], key: &[u8]) -> Result<(), SignerError>;
}
